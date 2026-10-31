package spec

import (
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

const (
	sudoRefreshFixtures = "testdata/sssd-sudo-refresh"
	sudoRefreshProgram  = "../../playbooks/apply/files/freeipa-sssd-sudo-refresh.py"
	sudoRefreshGate     = "Gate: every enrolled client finished a sudo full refresh"
)

// withSudoRefresh adds the sudo full-refresh helper to a harness's extra vars.
// The timeout is short so the failure scenarios do not wait a minute.
func withSudoRefresh(t *testing.T, vars map[string]any) map[string]any {
	t.Helper()
	program, err := os.ReadFile(sudoRefreshProgram)
	if err != nil {
		t.Fatal(err)
	}
	vars["ipa_sudo_refresh_program"] = string(program)
	vars["ipa_identity_sudo_refresh_timeout"] = 4
	return vars
}

func TestRegression_IdentitySSHCacheJournal(t *testing.T) {
	cmd := exec.Command("python3", "../../scripts/test-freeipa-ssh-key-cache.py")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("journal: %v\n%s", err, out)
	}
}

func TestRegression_IdentitySSHCacheStageScope(t *testing.T) {
	raw, err := os.ReadFile(sshKeysPlaybook)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	var production []any
	for _, value := range plays[0]["tasks"].([]any) {
		block := value.(map[string]any)
		for _, inner := range block["block"].([]any) {
			task := inner.(map[string]any)
			switch task["name"] {
			case "Resolve enrolled SSH key cache targets", "Gate: SSH cache targets must match the authorized stage",
				"Gate: pending SSH cache targets exist in this inventory", "Gate: pending SSH cache targets match the authorized stage":
				production = append(production, task)
			}
		}
	}
	if len(production) != 4 {
		t.Fatal("production stage-scope tasks not found")
	}
	for _, scenario := range []string{"current enrollment", "undefined plan", "retained cross-stage work", "retained missing target"} {
		// `--tags tagged` selects every tagged task, the SSH delegation too.
		for _, tag := range []string{"all", "tagged", "identity", "sshkeys", "client-cache", "users", "hbac", "freeipa_host_absent_inspect"} {
			t.Run(scenario+"/"+tag, func(t *testing.T) {
				groups := []string{"prod"}
				if scenario == "current enrollment" {
					groups = append(groups, "freeipa-client")
				}
				tasks := []any{map[string]any{
					"name": "cross-stage inventory fixture", "tags": []string{"always"},
					"ansible.builtin.add_host": map[string]any{"name": "client-prod", "groups": groups},
				}}
				tasks = append(tasks, production...)
				// Empty current users cannot suppress durable work for omitted users.
				vars := map[string]any{"stage": "sandbox", "ipa_active_users": []any{}}
				if scenario == "retained cross-stage work" || scenario == "retained missing target" {
					host := "client-prod"
					if scenario == "retained missing target" {
						host = "client-missing"
					}
					vars["ipa_ssh_cache_plan"] = map[string]any{"stdout": fmt.Sprintf(`{"work":[{"host":%q,"user":"omitted-user"}]}`, host)}
				}
				res := runGatewayTasks(t, t.TempDir(), tasks, vars, nil, "--tags", tag)
				mutation := tag != "hbac" && tag != "freeipa_host_absent_inspect"
				mustFail := mutation && scenario != "undefined plan"
				if (res.rc != 0) != mustFail {
					t.Fatalf("tag=%s rc=%d failures=%v\n%s", tag, res.rc, res.failures, res.raw)
				}
				if mustFail && scenario != "current enrollment" && !strings.Contains(fmt.Sprint(res.failures), "Gate: pending SSH cache targets") {
					t.Fatalf("retained work failed outside its actual-plan authorization gate: %v", res.failures)
				}
			})
		}
	}
}

// identityRecoveryGate is the run-tag condition that records the non-key
// refresh obligation under every selection that can change IPA.
const identityRecoveryGate = "ansible_run_tags | intersect(['all', 'tagged'] + ipa_identity_cache_recovery_tags) | length > 0"

// Keep the legacy non-key refresh predicate complete, without letting SSH-only
// changes or journal writes cause a fleet-wide cache flush. Every tag that
// selects a mutation must also record its refresh obligation before the
// mutation and settle it after: `--tags users` once changed IPA without
// either, and the next full apply then skipped the refresh (#138 review).
func TestRegression_IdentitySSHCacheNonKeyMutationCoverage(t *testing.T) {
	raw, err := os.ReadFile(sshKeysPlaybook)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	type entry struct {
		task  map[string]any
		order int
		tags  []string // including tags inherited from enclosing blocks
	}
	var want []string
	var mutations []entry
	named := map[string]entry{}
	var walk func([]any, []string)
	walk = func(tasks []any, inherited []string) {
		for _, v := range tasks {
			task := v.(map[string]any)
			tags := slices.Clone(inherited)
			if own, ok := task["tags"].([]any); ok {
				for _, tag := range own {
					tags = append(tags, tag.(string))
				}
			}
			e := entry{task, len(named), tags}
			if name, ok := task["name"].(string); ok {
				named[name] = e
			}
			if reg, ok := task["register"].(string); ok && reg != "ipa_sshkey" {
				if changed, exists := task["changed_when"]; exists && changed != false {
					want = append(want, reg)
					mutations = append(mutations, e)
				}
			}
			for _, section := range []string{"block", "rescue", "always"} {
				if inner, ok := task[section].([]any); ok {
					walk(inner, tags)
				}
			}
		}
	}
	walk(plays[0]["tasks"].([]any), nil)
	playVars := plays[0]["vars"].(map[string]any)
	var got []string
	for _, v := range playVars["ipa_identity_cache_mutation_registers"].([]any) {
		got = append(got, v.(string))
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("non-key mutation registers = %v; want %v", got, want)
	}

	// The refresh and acknowledgement read the settlement, so their tags
	// must record it too.
	wantTags := map[string]bool{}
	for _, name := range []string{"Refresh SSSD caches on enrolled FreeIPA clients", "Acknowledge legacy authorization cache recovery"} {
		e, ok := named[name]
		if !ok {
			t.Fatalf("task %q not found", name)
		}
		for _, tag := range e.tags {
			wantTags[tag] = true
		}
	}
	prepare, settle := named["Prepare legacy authorization cache recovery"], named["Settle legacy authorization cache recovery"]
	for _, m := range mutations {
		if slices.Contains(m.tags, "always") || slices.Contains(m.tags, "never") {
			t.Errorf("mutation %v is tagged %v; the recovery gate cannot follow it", m.task["register"], m.tags)
		}
		for _, tag := range m.tags {
			wantTags[tag] = true
		}
		if m.order < prepare.order || m.order > settle.order {
			t.Errorf("mutation %v runs outside prepare (#%d) … settle (#%d): #%d", m.task["register"], prepare.order, settle.order, m.order)
		}
	}
	var recovery []string
	for _, v := range playVars["ipa_identity_cache_recovery_tags"].([]any) {
		recovery = append(recovery, v.(string))
	}
	var wantList []string
	for tag := range wantTags {
		wantList = append(wantList, tag)
	}
	slices.Sort(recovery)
	slices.Sort(wantList)
	if !slices.Equal(recovery, wantList) {
		t.Errorf("ipa_identity_cache_recovery_tags = %v; want %v", recovery, wantList)
	}
	// Tagged prepare/settle would be skipped by `--skip-tags <one mutation
	// tag>` while other mutations still run; `always` + the run-tag gate is
	// selected exactly when some mutation is.
	for _, name := range []string{"Prepare legacy authorization cache recovery", "Settle legacy authorization cache recovery", "Report deferred authorization cache refresh"} {
		e, ok := named[name]
		if !ok {
			t.Fatalf("task %q not found", name)
		}
		if !slices.Equal(e.tags, []string{"always"}) || !strings.Contains(fmt.Sprint(e.task["when"]), identityRecoveryGate) {
			t.Errorf("%s: tags=%v when=%v; want [always] gated by %q", name, e.tags, e.task["when"], identityRecoveryGate)
		}
	}
}

// A non-key change made by a tagged run that does not refresh SSSD, or by a
// run interrupted after IPA committed it, must be refreshed by the next apply
// that does, even when that apply finds nothing left to change. Production
// prepare → user-mod → settle → report → refresh → ack tasks run; only the
// ipa/sss_cache processes are fakes (#138 review).
func TestRegression_IdentitySSHCacheTaggedNonKeyRecovery(t *testing.T) {
	dir := t.TempDir()
	helper, err := os.ReadFile("../../playbooks/apply/files/freeipa-ssh-key-cache.py")
	if err != nil {
		t.Fatal(err)
	}
	write := installSSHCacheFakes(t, dir)
	raw, err := os.ReadFile(sshKeysPlaybook)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	tasks := []any{}
	for _, host := range []string{"client-a", "client-b"} {
		tasks = append(tasks, map[string]any{"name": "test inventory " + host, "tags": []string{"always"},
			"ansible.builtin.add_host": map[string]any{"name": host, "groups": "freeipa-client", "ansible_connection": "local"}})
	}
	const userMod = "Reconcile user first/last names"
	var userModTags []string
	var collect func([]any)
	collect = func(all []any) {
		for _, value := range all {
			task := value.(map[string]any)
			switch task["name"] {
			case "Prepare legacy authorization cache recovery", userMod, "Settle legacy authorization cache recovery",
				"Report deferred authorization cache refresh", "Refresh SSSD caches on enrolled FreeIPA clients",
				sudoRefreshGate, "Acknowledge legacy authorization cache recovery":
				delete(task, "become") // test runs unprivileged; production uses root
				if task["name"] == "Refresh SSSD caches on enrolled FreeIPA clients" {
					task["environment"] = map[string]any{"CACHE_TEST_HOST": "{{ item }}", "CACHE_TEST_DIR": dir}
				}
				if task["name"] == userMod {
					for _, tag := range task["tags"].([]any) {
						userModTags = append(userModTags, tag.(string))
					}
				}
				tasks = append(tasks, task)
			}
			if inner, ok := task["block"].([]any); ok {
				collect(inner)
			}
		}
	}
	collect(plays[0]["tasks"].([]any))
	if len(tasks) != 9 || len(userModTags) == 0 {
		t.Fatalf("production recovery tasks not found: %d tasks, user-mod tags %v", len(tasks), userModTags)
	}
	statePath := filepath.Join(dir, "journal.json")
	playVars := plays[0]["vars"].(map[string]any)
	vars := withSudoRefresh(t, map[string]any{"ipa_domain": "ipa.test", "ipa_ssh_cache_program": string(helper),
		"ipa_identity_ssh_cache_state_file":     statePath,
		"ipa_identity_refresh_sssd_cache":       true,
		"ipa_identity_cache_mutation_registers": playVars["ipa_identity_cache_mutation_registers"],
		"ipa_identity_cache_recovery_tags":      playVars["ipa_identity_cache_recovery_tags"],
		"ipa_active_users":                      []any{map[string]any{"name": "alice", "first": "Alice", "last": "Example", "login_shell": "/bin/zsh"}}})
	refreshed := []string{"client-a/*", "client-b/*"}
	const deferredNotice = "Report deferred authorization cache refresh"
	step := func(label, modified string, success bool, want []string, args ...string) ag82Run {
		t.Helper()
		write("modified", modified)
		write("calls", "")
		result := runGatewayTasks(t, dir, tasks, vars, nil, args...)
		if (result.rc == 0) != success {
			t.Fatalf("%s %v: rc=%d failures=%v\n%s", label, args, result.rc, result.failures, result.raw)
		}
		if got := readSSHCacheCalls(t, dir); !slices.Equal(got, want) {
			t.Fatalf("%s %v: cache calls=%v; want %v; failures=%v\n%s", label, args, got, want, result.failures, result.raw)
		}
		return result
	}
	noticed := func(result ag82Run) bool {
		return strings.Contains(strings.Join(result.messages, "\n"), deferredNotice+":")
	}
	removeJournal := func() {
		t.Helper()
		if err := os.Remove(statePath); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	// A journal that already recorded a completed run. Starting from no
	// journal would make every first run dirty (adoption) and hide whether
	// the scenario's own run recorded its change.
	reset := func() {
		t.Helper()
		write("journal.json", `{"version": 1, "domain": "ipa.test", "users": {}, "auth_pending": false}`)
		if err := os.Remove(filepath.Join(dir, "interrupt")); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	pending := func() bool {
		t.Helper()
		state, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Contains(string(state), `"auth_pending": true`)
	}

	// Adoption: no journal shows that earlier runs reached every client.
	removeJournal()
	step("adoption no-op", "no", true, refreshed)
	step("completed no-op after adoption", "no", true, nil)

	// The reviewer's reproduction, for every tag that selects the user-mod
	// task: a tagged change, then an identical full roster that IPA reports
	// as "no modifications".
	for _, tag := range userModTags {
		reset()
		var want []string
		if tag == "identity" {
			want = refreshed // the refresh's own tag delivers in the same run
		}
		tagged := step("tagged change", "yes", true, want, "--tags", tag)
		if noticed(tagged) == (tag == "identity") {
			t.Fatalf("--tags %s: deferred-refresh notice=%v\n%s", tag, noticed(tagged), tagged.raw)
		}
		if tag != "identity" {
			step("identical full apply after --tags "+tag, "no", true, refreshed)
		}
		step("completed no-op after --tags "+tag, "no", true, nil)
	}

	// Interrupted after IPA committed: no settlement, so the retry (tagged
	// or full) still owes the refresh even though IPA now has nothing to do.
	for _, retry := range [][]string{{"--tags", "users"}, nil} {
		reset()
		write("interrupt", "yes")
		step("interrupted tagged change", "yes", false, nil, "--tags", "users")
		if err := os.Remove(filepath.Join(dir, "interrupt")); err != nil {
			t.Fatal(err)
		}
		if retry != nil {
			if !noticed(step("tagged retry", "no", true, nil, retry...)) {
				t.Fatal("tagged retry did not report the deferred refresh")
			}
		}
		step("full retry", "no", true, refreshed)
		step("completed no-op after retry", "no", true, nil)
	}

	// Skipping the refresh defers it; skipping the mutation's own tag still
	// delivers an earlier obligation; `--tags tagged` selects everything.
	reset()
	if !noticed(step("change with refresh skipped", "yes", true, nil, "--skip-tags", "client-cache")) {
		t.Fatal("--skip-tags client-cache did not report the deferred refresh")
	}
	step("skip the mutation tag", "no", true, refreshed, "--skip-tags", "users")
	step("completed no-op", "no", true, nil)
	reset()
	step("--tags tagged", "yes", true, refreshed, "--tags", "tagged")
	step("completed no-op", "no", true, nil)

	// A read-only selection neither records, settles nor delivers: it does
	// not even create a journal, and keeps an existing obligation.
	removeJournal()
	step("read-only inspection without journal", "yes", true, nil, "--tags", "freeipa_host_absent_inspect")
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("read-only selection wrote the journal: %v", err)
	}
	reset()
	step("pending change", "yes", true, nil, "--tags", "users")
	step("read-only inspection", "yes", true, nil, "--tags", "freeipa_host_absent_inspect")
	if !pending() {
		t.Fatal("read-only selection cleared the pending refresh")
	}
	step("full apply", "no", true, refreshed)

	// With the refresh option off the change is still recorded, so turning
	// the option back on delivers it.
	reset()
	if noticed(step("change with refresh disabled", "yes", true, nil, "-e", "ipa_identity_refresh_sssd_cache=false")) {
		t.Fatal("refresh disabled: the notice reports a deferral the operator turned off")
	}
	if !pending() {
		t.Fatal("refresh disabled: change not recorded")
	}
	step("refresh re-enabled", "no", true, refreshed)
	step("completed no-op", "no", true, nil)
}

// installSSHCacheFakes puts fake ipa/sss_cache/sss_ssh_authorizedkeys first
// on PATH. `ipa` prints #115's real user-mod captures: "Modified user" while
// dir/modified is "yes", otherwise "no modifications". Every sss_cache call
// is appended to dir/calls as host/user (host/* for a global -E). The
// returned function writes a control file under dir.
func installSSHCacheFakes(t *testing.T, dir string) func(name, value string) {
	t.Helper()
	for _, sub := range []string{"source", "cache"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// dir/interrupt: IPA commits the change, then the run dies before the
	// result reaches Ansible (the next call reports no modifications).
	write("ipa", `#!/usr/bin/env python3
import os,sys
from pathlib import Path
d=Path(os.environ['CACHE_TEST_DIR'])
if d.joinpath('interrupt').exists():
 d.joinpath('modified').write_text('no')
 sys.exit(137)
if d.joinpath('modified').read_text() == 'yes':
 print(d.joinpath('modified.stdout').read_text(), end='')
 sys.exit(0)
print(d.joinpath('noop.stderr').read_text(), end='', file=sys.stderr)
sys.exit(1)
`)
	for name, fixture := range map[string]string{"modified.stdout": "user-mod-modified.stdout", "noop.stderr": "user-mod-no-modifications.stderr"} {
		content, err := os.ReadFile(filepath.Join(sshKeysFixtures, fixture))
		if err != nil {
			t.Fatal(err)
		}
		write(name, string(content))
	}
	write("sss_cache", `#!/usr/bin/env python3
import os,sys
from pathlib import Path
d=Path(os.environ['CACHE_TEST_DIR']); host=os.environ['CACHE_TEST_HOST']; user=sys.argv[-1]
if user == '-E':
 with d.joinpath('calls').open('a') as f: f.write(host+'/*\n')
 sys.exit(9 if d.joinpath('fail-global-'+host).exists() else 0)
with d.joinpath('calls').open('a') as f: f.write(host+'/'+user+'\n')
if d.joinpath('fail-'+host).exists(): sys.exit(9)
d.joinpath('cache',host+'-'+user).write_text(d.joinpath('source',user).read_text())
`)
	write("sss_ssh_authorizedkeys", `#!/usr/bin/env python3
import os,sys
from pathlib import Path
d=Path(os.environ['CACHE_TEST_DIR']); host=os.environ['CACHE_TEST_HOST']; user=sys.argv[-1]
if d.joinpath('lookup-fail-'+host).exists(): sys.exit(1)
print(d.joinpath('cache',host+'-'+user).read_text(), end='')
`)
	// The sudo full-refresh oracle: `ldbsearch` prints the real captured
	// output (testdata/sssd-sudo-refresh) with dir/marker-<host> substituted
	// for the epoch; a restart advances it to now unless dir/no-refresh-<host>
	// exists (SSSD cannot reach FreeIPA). dir/ldb-mode-<host> picks another
	// capture. Restarts are logged to dir/restarts.
	write("ldbsearch", `#!/usr/bin/env python3
import os,re,sys
from pathlib import Path
d=Path(os.environ['CACHE_TEST_DIR']); host=os.environ.get('CACHE_TEST_HOST',''); fx=Path(os.environ['SUDO_REFRESH_FIXTURES'])
mode=d.joinpath('ldb-mode-'+host).read_text() if d.joinpath('ldb-mode-'+host).exists() else 'ldbsearch-marker-ubuntu-2.9.4'
marker=d.joinpath('marker-'+host).read_text() if d.joinpath('marker-'+host).exists() else '1'
# The real command line the helper must send (captured on both OS families):
# the domain's cache database, the sudorules container, base scope, the marker.
import re as _re
a=sys.argv[1:]
m=_re.fullmatch(r'/var/lib/sss/db/cache_(.+)\.ldb', a[1]) if len(a) == 7 and a[0] == '-H' else None
if not m or a[2:] != ['-b', 'cn=sudorules,cn=custom,cn='+m.group(1)+',cn=sysdb', '-s', 'base', 'sudoLastFullRefreshTime']:
 print('unexpected ldbsearch arguments: %r' % a, file=sys.stderr); sys.exit(2)
out=fx.joinpath(mode+'.stdout'); err=fx.joinpath(mode+'.stderr')
if out.exists(): print(re.sub(r'(sudoLastFullRefreshTime: )\d+', lambda m: m.group(1)+marker, out.read_text()), end='')
if err.exists(): print(err.read_text(), end='', file=sys.stderr)
sys.exit(1 if mode == 'ldbsearch-no-db' else 0)
`)
	write("systemctl", `#!/usr/bin/env python3
import os,sys,time
from pathlib import Path
d=Path(os.environ['CACHE_TEST_DIR']); host=os.environ.get('CACHE_TEST_HOST','')
if sys.argv[1:] != ['restart','sssd']: sys.exit(0)
with d.joinpath('restarts').open('a') as f: f.write(host+'\n')
if d.joinpath('fail-restart-'+host).exists(): sys.exit(5)
if not d.joinpath('no-refresh-'+host).exists(): d.joinpath('marker-'+host).write_text(str(int(time.time())))
`)
	for _, binary := range []string{"ipa", "sss_cache", "sss_ssh_authorizedkeys", "ldbsearch", "systemctl"} {
		if err := os.Chmod(filepath.Join(dir, binary), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CACHE_TEST_DIR", dir)
	fixtures, err := filepath.Abs(sudoRefreshFixtures)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SUDO_REFRESH_FIXTURES", fixtures)
	return write
}

// readSSHCacheCalls returns the sorted sss_cache calls recorded since the
// last reset of dir/calls.
func readSSHCacheCalls(t *testing.T, dir string) []string {
	t.Helper()
	calls, err := os.ReadFile(filepath.Join(dir, "calls"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(string(calls))
	slices.Sort(lines)
	return lines
}

// Runs the production prepare → IPA → settle → delegate → ack → failure gate
// tasks with named localhost aliases. Only the IPA/SSSD processes are fakes;
// journal persistence, Ansible loops, tags, delegation and failure gates are real.
func TestRegression_IdentitySSHCacheRuntime(t *testing.T) {
	dir := t.TempDir()
	helper, err := os.ReadFile("../../playbooks/apply/files/freeipa-ssh-key-cache.py")
	if err != nil {
		t.Fatal(err)
	}
	keyfile := filepath.Join(dir, "key")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", keyfile).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	pub, err := os.ReadFile(keyfile + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	key := strings.TrimSpace(string(pub))
	write := installSSHCacheFakes(t, dir)
	write("source/alice", key+"\n")
	write("source/bob", "")
	write("modified", "yes")
	raw, err := os.ReadFile(sshKeysPlaybook)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	// Delegation resolves connection settings from host variables. Declare
	// the provider explicitly instead of relying only on play connection=local.
	tasks := []any{map[string]any{"name": "test inventory provider", "tags": []string{"always"},
		"ansible.builtin.add_host": map[string]any{"name": "localhost", "ansible_connection": "local", "ansible_host": "127.0.0.1", "ansible_port": 22}}}
	for _, host := range []string{"client-a", "client-b"} {
		connection := "local"
		address := "127.0.0.3"
		if host == "client-b" {
			connection = "{{ 'ssh' if cache_test_unreachable | default(false) else 'local' }}"
			address = "127.0.0.2"
		}
		// Keep the deliberately unreachable SSH alias distinct from implicit
		// localhost/127.0.0.1. Otherwise Ansible can reuse its connection state
		// for the provider and the failure fixture also breaks localhost.
		tasks = append(tasks, map[string]any{"name": "test inventory " + host, "tags": []string{"always"},
			"ansible.builtin.add_host": map[string]any{"name": host, "groups": "freeipa-client", "ansible_connection": connection, "ansible_host": address, "ansible_port": 1}})
	}
	tasks = append(tasks, map[string]any{"name": "historical inventory alias", "tags": []string{"always"},
		"ansible.builtin.add_host": map[string]any{"name": "old-client", "groups": "{{ cache_test_old_groups | default('sandbox') }}", "ansible_connection": "local"}})
	var collect func([]any)
	collect = func(all []any) {
		for _, value := range all {
			task := value.(map[string]any)
			name, _ := task["name"].(string)
			tags, _ := task["tags"].([]any)
			if slices.Contains(tags, any("sshkeys")) || strings.Contains(name, "legacy authorization cache recovery") || name == "Refresh SSSD caches on enrolled FreeIPA clients" || name == sudoRefreshGate {
				delete(task, "become") // test runs unprivileged; production uses root
				if strings.HasPrefix(name, "Invalidate and verify") {
					task["environment"] = map[string]any{"CACHE_TEST_HOST": "{{ item.host }}", "CACHE_TEST_DIR": dir}
				}
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
	vars := withSudoRefresh(t, map[string]any{"ipa_domain": "ipa.test", "stage": "sandbox", "ipa_ssh_cache_program": string(helper),
		"ipa_identity_ssh_cache_state_file":     filepath.Join(dir, "journal.json"),
		"ipa_identity_refresh_sssd_cache":       true,
		"ipa_identity_cache_mutation_registers": plays[0]["vars"].(map[string]any)["ipa_identity_cache_mutation_registers"],
		"ipa_identity_cache_recovery_tags":      plays[0]["vars"].(map[string]any)["ipa_identity_cache_recovery_tags"]})
	run := func(keys []any, deferred []string, check bool) ag82Run {
		t.Helper()
		vars["ipa_active_users"] = []any{map[string]any{"name": "alice", "ssh_keys": keys}, map[string]any{"name": "bob", "ssh_keys": []any{}}, map[string]any{"name": "unmanaged"}}
		if vars["cache_test_omit_users"] == true {
			vars["ipa_active_users"] = []any{}
		}
		vars["pilot_deferred_hosts"] = deferred
		write("calls", "")
		var args []string
		if check {
			args = []string{"--check", "--diff"}
		}
		if tag, ok := vars["cache_test_tag"].(string); ok && tag != "all" {
			args = append(args, "--tags", tag)
		}
		return runGatewayTasks(t, dir, tasks, vars, nil, args...)
	}
	assertRun := func(result ag82Run, success bool, hosts ...string) {
		t.Helper()
		if (result.rc == 0) != success {
			t.Fatalf("rc=%d failures=%v\n%s", result.rc, result.failures, result.raw)
		}
		lines := readSSHCacheCalls(t, dir)
		slices.Sort(hosts)
		if !slices.Equal(lines, hosts) {
			t.Fatalf("cache calls=%v; want %v; failures=%v\n%s", lines, hosts, result.failures, result.raw)
		}
	}
	all := []string{"client-a/alice", "client-a/bob", "client-b/alice", "client-b/bob", "localhost/alice", "localhost/bob"}
	assertRun(run([]any{key}, nil, true), true)
	if _, err := os.Stat(filepath.Join(dir, "journal.json")); !os.IsNotExist(err) {
		t.Fatal("check mode wrote journal")
	}
	// Adoption: every managed pair, plus one global refresh because no
	// journal shows that earlier runs reached every client.
	assertRun(run([]any{key}, nil, false), true, append(slices.Clone(all), "client-a/*", "client-b/*")...)
	write("modified", "no")
	assertRun(run([]any{key}, nil, false), true)
	write("source/alice", "")
	write("modified", "yes")
	// The fake reports both users modified, so both are invalidated; #115's
	// real no-key/no-modifications capture is used by the no-op runs above.
	assertRun(run([]any{}, nil, false), true, all...)
	write("source/alice", key+"\n")
	assertRun(run([]any{key}, nil, false), true, all...)
	write("source/alice", "")
	write("fail-client-a", "yes")
	partial := run([]any{}, nil, false)
	// One bounded retry after an invalidation error; other clients still run.
	assertRun(partial, false, append(slices.Clone(all), "client-a/alice", "client-a/bob")...)
	if !strings.Contains(fmt.Sprint(partial.failures), "PARTIAL") {
		t.Fatalf("partial failure not surfaced: %v", partial.failures)
	}
	if err := os.Remove(filepath.Join(dir, "fail-client-a")); err != nil {
		t.Fatal(err)
	}
	write("modified", "no")
	assertRun(run([]any{}, nil, false), true, "client-a/alice", "client-a/bob")
	assertRun(run([]any{}, nil, false), true)
	write("source/alice", key+"\n")
	write("modified", "yes")
	assertRun(run([]any{key}, []string{"client-b"}, false), false, "client-a/alice", "client-a/bob", "localhost/alice", "localhost/bob")
	write("modified", "no")
	assertRun(run([]any{key}, nil, false), true, "client-b/alice", "client-b/bob")
	assertRun(run([]any{key}, nil, false), true)
	write("source/alice", "")
	write("modified", "yes")
	vars["cache_test_unreachable"] = true
	assertRun(run([]any{}, nil, false), false, "client-a/alice", "client-a/bob", "localhost/alice", "localhost/bob")
	vars["cache_test_unreachable"] = false
	write("modified", "no")
	assertRun(run([]any{}, nil, false), true, "client-b/alice", "client-b/bob")
	write("source/alice", key+"\n")
	write("modified", "yes")
	write("lookup-fail-client-b", "yes")
	assertRun(run([]any{key}, nil, false), false, all...)
	if err := os.Remove(filepath.Join(dir, "lookup-fail-client-b")); err != nil {
		t.Fatal(err)
	}
	write("modified", "no")
	assertRun(run([]any{key}, nil, false), true, "client-b/alice", "client-b/bob")
	vars["ipa_user_mod"] = map[string]any{"changed": true}
	write("fail-global-client-a", "yes")
	assertRun(run([]any{key}, nil, false), false, "client-a/*", "client-b/*")
	if err := os.Remove(filepath.Join(dir, "fail-global-client-a")); err != nil {
		t.Fatal(err)
	}
	vars["ipa_user_mod"] = map[string]any{"changed": false}
	assertRun(run([]any{key}, nil, false), true, "client-a/*", "client-b/*")
	assertRun(run([]any{key}, nil, false), true)
	// A non-key mutation must remain recoverable while any client is deferred.
	vars["ipa_user_mod"] = map[string]any{"changed": true}
	assertRun(run([]any{key}, []string{"client-b"}, false), true, "client-a/*")
	vars["ipa_user_mod"] = map[string]any{"changed": false}
	assertRun(run([]any{key}, nil, false), true, "client-a/*", "client-b/*")
	assertRun(run([]any{key}, nil, false), true)
	// Crash after prepare, before settle/refresh: recovery is conservative even
	// when the next reconciliation finds no additional authorization changes.
	statePath := filepath.Join(dir, "journal.json")
	crash := exec.Command("python3", "-c", string(helper), "auth_prepare", statePath)
	crash.Stdin = strings.NewReader(`{"domain":"ipa.test"}`)
	if out, err := crash.CombinedOutput(); err != nil {
		t.Fatalf("crash prepare: %v %s", err, out)
	}
	assertRun(run([]any{key}, nil, false), true, "client-a/*", "client-b/*")
	assertRun(run([]any{key}, nil, false), true)

	// Retained work must be authorized from the current inventory, regardless
	// of whether the current roster still manages that user and under every
	// supported mutation tag. Actual production prepare/settle/gate/delegate
	// tasks execute; rejected plans may never call either SSSD process.
	for _, omitted := range []bool{false, true} {
		for _, host := range []string{"old-client", "missing-client"} {
			for _, tag := range []string{"all", "identity", "sshkeys", "users", "client-cache"} {
				raw, err := os.ReadFile(statePath)
				if err != nil {
					t.Fatal(err)
				}
				var state map[string]any
				if err := json.Unmarshal(raw, &state); err != nil {
					t.Fatal(err)
				}
				users := state["users"].(map[string]any)
				users["alice"].(map[string]any)["pending"] = []string{host}
				raw, err = json.Marshal(state)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(statePath, raw, 0600); err != nil {
					t.Fatal(err)
				}
				vars["cache_test_omit_users"] = omitted
				vars["cache_test_old_groups"] = "prod"
				vars["cache_test_tag"] = tag
				result := run([]any{key}, nil, false)
				assertRun(result, false)
				if !strings.Contains(fmt.Sprint(result.failures), "Gate: pending SSH cache targets") {
					t.Fatalf("wrong failure: %v", result.failures)
				}
				raw, err = os.ReadFile(statePath)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(raw), host) {
					t.Fatalf("lost unfinished work for %s", host)
				}
			}
		}
	}
}
