package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const resolverTasksPath = "../../playbooks/apply/tasks/freeipa-dns-client-resolver.yml"

const (
	resolverSnapshotTask     = "FreeIPA DNS client — snapshot resolver state before changing it"
	resolverBlockTask        = "FreeIPA DNS client — configure DNS resolver and verify it actually resolves via FreeIPA"
	resolverRestoreFilesTask = "ROLLBACK — restore resolver files from the pre-apply snapshot"
	resolverReloadTask       = "ROLLBACK — reload systemd-resolved and netplan from the restored files (Debian)"
	resolverRestoreNMTask    = "ROLLBACK — restore the connection's DNS settings (EL NetworkManager)"
)

// resolverTaskList parses tasks/freeipa-dns-client-resolver.yml as a list of
// task mappings.
func resolverTaskList(t *testing.T) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(resolverTasksPath)
	if err != nil {
		t.Fatal(err)
	}
	var tasks []map[string]any
	if err := yaml.Unmarshal(raw, &tasks); err != nil {
		t.Fatal(err)
	}
	return tasks
}

func taskIndexByName(tasks []map[string]any, name string) int {
	for i, task := range tasks {
		if task["name"] == name {
			return i
		}
	}
	return -1
}

func resolverRescue(t *testing.T, tasks []map[string]any) []map[string]any {
	t.Helper()
	i := taskIndexByName(tasks, resolverBlockTask)
	if i < 0 {
		t.Fatalf("block task %q not found", resolverBlockTask)
	}
	raw, ok := tasks[i]["rescue"].([]any)
	if !ok {
		t.Fatalf("block task %q has no rescue list", resolverBlockTask)
	}
	var rescue []map[string]any
	for _, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			t.Fatalf("rescue entry is %T, want a mapping", r)
		}
		rescue = append(rescue, m)
	}
	return rescue
}

func shellText(t *testing.T, task map[string]any) string {
	t.Helper()
	s, ok := task["ansible.builtin.shell"].(string)
	if !ok {
		t.Fatalf("task %q is not a free-form ansible.builtin.shell task", task["name"])
	}
	return s
}

// TestRegression_FreeipaDNSClientRollback_Structure locks the 2026-09-24
// rollback redesign (docs/evidence/freeipa-dns-client/2026-09-24-583df40.md):
// the rescue used to restore only /etc/resolv.conf from the copy task's
// backup, which on Ubuntu left the resolved and netplan drop-ins pointing
// at the failed server, restored a post-restart copy, and turned the stub
// symlink into a regular file. The snapshot must be taken before the block
// (a failed snapshot then stops the play before anything changes), and the
// rescue must restore from it and reload both resolvers.
func TestRegression_FreeipaDNSClientRollback_Structure(t *testing.T) {
	tasks := resolverTaskList(t)
	snap := taskIndexByName(tasks, resolverSnapshotTask)
	block := taskIndexByName(tasks, resolverBlockTask)
	if snap < 0 || block < 0 || snap > block {
		t.Fatalf("snapshot task (index %d) must exist and come before the block (index %d)", snap, block)
	}
	st := tasks[snap]
	if st["changed_when"] != false {
		t.Errorf("snapshot task: changed_when = %v, want false (it is refreshed every run; a changed result would break the changed=0 idempotency check)", st["changed_when"])
	}
	if st["when"] != "not ansible_check_mode" {
		t.Errorf("snapshot task: when = %v, want %q", st["when"], "not ansible_check_mode")
	}
	script := shellText(t, st)
	for _, want := range []string{
		"cp -a --no-dereference",
		"/etc/resolv.conf",
		"freeipa_dns_client_resolved_dropin_path",
		"freeipa_dns_client_netplan_dropin_path",
		"ipv4.dns ipv4.dns-search ipv4.ignore-auto-dns",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("snapshot script must contain %q", want)
		}
	}

	rescue := resolverRescue(t, tasks)
	var names []string
	for _, r := range rescue {
		names = append(names, r["name"].(string))
	}
	want := []string{resolverRestoreFilesTask, resolverReloadTask, resolverRestoreNMTask, "ROLLBACK — surface the original failure"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("rescue tasks = %q, want %q", names, want)
	}
	for _, r := range rescue[:3] {
		if r["failed_when"] != false {
			t.Errorf("%q: failed_when = %v, want false (a failed step must not skip the rest of the rollback or the final message)", r["name"], r["failed_when"])
		}
		if _, ok := r["register"]; !ok {
			t.Errorf("%q must register its result for the final message", r["name"])
		}
	}
	reload := shellText(t, rescue[1])
	for _, want := range []string{"systemctl restart systemd-resolved", "netplan apply"} {
		if !strings.Contains(reload, want) {
			t.Errorf("Debian reload step must contain %q", want)
		}
	}
	if !strings.Contains(shellText(t, rescue[2]), "nmcli connection modify") {
		t.Errorf("EL rollback step must restore the connection with nmcli connection modify")
	}

	raw, err := os.ReadFile(resolverTasksPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "ls -t /etc/resolv.conf.") {
		t.Errorf("rescue must not pick the newest copy-module backup any more; restore from the pre-apply snapshot")
	}
}

// TestRegression_FreeipaDNSClientDigInstallUsesAptFramework locks the other
// 2026-09-24 finding: plain ansible.builtin.apt for `dnsutils` hit a 404 on
// a stale apt index and failed the apply before the resolver block.
func TestRegression_FreeipaDNSClientDigInstallUsesAptFramework(t *testing.T) {
	tasks := resolverTaskList(t)
	i := taskIndexByName(tasks, "FreeIPA DNS client — install dig (Debian, apt framework)")
	if i < 0 {
		t.Fatal("dig install task not found")
	}
	task := tasks[i]
	inc, ok := task["ansible.builtin.include_tasks"].(map[string]any)
	if !ok || inc["file"] != "apt-package-install.yml" {
		t.Fatalf("dig install must include apt-package-install.yml, got %v", task["ansible.builtin.include_tasks"])
	}
	apply, _ := inc["apply"].(map[string]any)
	if !reflect.DeepEqual(apply["tags"], []any{"always"}) {
		t.Errorf("dig install apply.tags = %v, want [always] (this shared file cannot name either caller's row tags)", apply["tags"])
	}
	vars, _ := task["vars"].(map[string]any)
	if !reflect.DeepEqual(vars["pilot_apt_packages"], []any{"bind9-dnsutils"}) {
		t.Errorf("pilot_apt_packages = %v, want [bind9-dnsutils] (dnsutils is a transitional package)", vars["pilot_apt_packages"])
	}
	for _, task := range tasks {
		for _, key := range []string{"ansible.builtin.apt", "apt"} {
			if _, ok := task[key]; ok {
				t.Errorf("task %q installs with plain %s; use the apt framework", task["name"], key)
			}
		}
	}
}

// TestRegression_FreeipaDNSClientIncludeAppliesTags locks that the resolver
// include in freeipa-dns-client-apply.yml passes its row tags down with
// `apply`; without it `--tags C3` ran the include and skipped every
// resolver task (AGENTS.md §4.5 point 8).
func TestRegression_FreeipaDNSClientIncludeAppliesTags(t *testing.T) {
	raw, err := os.ReadFile("../../playbooks/apply/freeipa-dns-client-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, play := range plays {
		tasks, _ := play["tasks"].([]any)
		for _, rawTask := range tasks {
			task, _ := rawTask.(map[string]any)
			inc, ok := task["ansible.builtin.include_tasks"].(map[string]any)
			if !ok || inc["file"] != "tasks/freeipa-dns-client-resolver.yml" {
				continue
			}
			found = true
			apply, _ := inc["apply"].(map[string]any)
			if !reflect.DeepEqual(apply["tags"], task["tags"]) {
				t.Errorf("resolver include apply.tags = %v, want the include's own tags %v", apply["tags"], task["tags"])
			}
		}
	}
	if !found {
		t.Fatal("no `include_tasks: {file: tasks/freeipa-dns-client-resolver.yml}` found in freeipa-dns-client-apply.yml")
	}
}

// rollbackSandbox renders the snapshot and restore scripts with every host
// path moved under a temporary root, so the real script text can run
// without root and without touching /etc.
type rollbackSandbox struct {
	root, resolv, resolved, netplan, snap, bin string
	snapshot, restore, restoreNM               string
}

func newRollbackSandbox(t *testing.T, osFamily string) *rollbackSandbox {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	root := t.TempDir()
	sb := &rollbackSandbox{
		root:     root,
		resolv:   filepath.Join(root, "etc/resolv.conf"),
		resolved: filepath.Join(root, "etc/systemd/resolved.conf.d/90-pilot-freeipa-dns-client.conf"),
		netplan:  filepath.Join(root, "etc/netplan/99-pilot-freeipa-dns-client.yaml"),
		snap:     filepath.Join(root, "var/lib/pilot/freeipa-dns-client/pre-apply"),
		bin:      filepath.Join(root, "bin"),
	}
	for _, d := range []string{filepath.Dir(sb.resolved), filepath.Dir(sb.netplan), filepath.Join(root, "run"), sb.bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	render := func(s string) string {
		// /etc/resolv.conf first: the sandbox paths inserted below
		// contain that substring themselves.
		s = strings.ReplaceAll(s, "/etc/resolv.conf", sb.resolv)
		s = strings.ReplaceAll(s, "{{ freeipa_dns_client_snapshot_dir | quote }}", sb.snap)
		s = strings.ReplaceAll(s, "{{ freeipa_dns_client_resolved_dropin_path | quote }}", sb.resolved)
		s = strings.ReplaceAll(s, "{{ freeipa_dns_client_netplan_dropin_path | quote }}", sb.netplan)
		s = strings.ReplaceAll(s, "{{ ansible_os_family | quote }}", osFamily)
		if strings.Contains(s, "{{") {
			t.Fatalf("unrendered Jinja left in script:\n%s", s)
		}
		return s
	}
	tasks := resolverTaskList(t)
	sb.snapshot = render(shellText(t, tasks[taskIndexByName(tasks, resolverSnapshotTask)]))
	rescue := resolverRescue(t, tasks)
	sb.restore = render(shellText(t, rescue[0]))
	sb.restoreNM = render(shellText(t, rescue[2]))
	return sb
}

func (sb *rollbackSandbox) run(t *testing.T, script string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+sb.bin+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return string(out), ee.ExitCode()
		}
		t.Fatalf("run script: %v", err)
	}
	return string(out), 0
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// mutateLikeTheBlock writes what the resolver block writes on Ubuntu:
// /etc/resolv.conf becomes a regular managed file (copy with follow: false
// replaces the symlink), and both drop-ins get pilot content.
func (sb *rollbackSandbox) mutateLikeTheBlock(t *testing.T) {
	t.Helper()
	if err := os.Remove(sb.resolv); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	writeFile(t, sb.resolv, "# pilot-freeipa-dns-client\nnameserver 192.0.2.53\n")
	writeFile(t, sb.resolved, "[Resolve]\nDNS=192.0.2.53\n")
	writeFile(t, sb.netplan, "network: {}\n")
}

func TestFreeipaDNSClientRollback_FirstRunOnUbuntuRestoresSymlinkAndRemovesDropins(t *testing.T) {
	sb := newRollbackSandbox(t, "Debian")
	writeFile(t, filepath.Join(sb.root, "run/stub-resolv.conf"), "nameserver 127.0.0.53\n")
	if err := os.Symlink("../run/stub-resolv.conf", sb.resolv); err != nil {
		t.Fatal(err)
	}
	if out, rc := sb.run(t, sb.snapshot); rc != 0 {
		t.Fatalf("snapshot rc=%d:\n%s", rc, out)
	}
	sb.mutateLikeTheBlock(t)

	out, rc := sb.run(t, sb.restore)
	if rc != 0 {
		t.Fatalf("restore rc=%d:\n%s", rc, out)
	}
	target, err := os.Readlink(sb.resolv)
	if err != nil || target != "../run/stub-resolv.conf" {
		t.Errorf("resolv.conf after restore: readlink = %q, %v; want the original symlink ../run/stub-resolv.conf", target, err)
	}
	for _, p := range []string{sb.resolved, sb.netplan} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s should be removed (it did not exist before the run), lstat err = %v", p, err)
		}
	}
	for _, want := range []string{
		sb.resolv + " restored",
		sb.resolved + " removed (did not exist before)",
		sb.netplan + " removed (did not exist before)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("restore output missing %q:\n%s", want, out)
		}
	}
}

func TestFreeipaDNSClientRollback_RerunRestoresPreviousContent(t *testing.T) {
	sb := newRollbackSandbox(t, "Debian")
	writeFile(t, sb.resolv, "nameserver 10.0.0.10\n")
	writeFile(t, sb.resolved, "[Resolve]\nDNS=10.0.0.10\n")
	writeFile(t, sb.netplan, "network: {version: 2}\n")
	if out, rc := sb.run(t, sb.snapshot); rc != 0 {
		t.Fatalf("snapshot rc=%d:\n%s", rc, out)
	}
	sb.mutateLikeTheBlock(t)

	if out, rc := sb.run(t, sb.restore); rc != 0 {
		t.Fatalf("restore rc=%d:\n%s", rc, out)
	}
	for path, want := range map[string]string{
		sb.resolv:   "nameserver 10.0.0.10\n",
		sb.resolved: "[Resolve]\nDNS=10.0.0.10\n",
		sb.netplan:  "network: {version: 2}\n",
	} {
		if got := readFile(t, path); got != want {
			t.Errorf("%s = %q, want the pre-apply content %q", path, got, want)
		}
	}
}

func TestFreeipaDNSClientRollback_NoSnapshotReportsAndLeavesFiles(t *testing.T) {
	sb := newRollbackSandbox(t, "Debian")
	sb.mutateLikeTheBlock(t)
	out, rc := sb.run(t, sb.restore)
	if rc != 1 || !strings.Contains(out, "no pre-apply snapshot at "+sb.snap+", files left unchanged") {
		t.Errorf("restore without a snapshot: rc=%d output %q; want rc=1 and the no-snapshot message", rc, out)
	}
	if got := readFile(t, sb.resolved); got != "[Resolve]\nDNS=192.0.2.53\n" {
		t.Errorf("drop-in changed without a snapshot: %q", got)
	}
}

func TestFreeipaDNSClientRollback_FailedRestoreIsReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory permission this test relies on")
	}
	sb := newRollbackSandbox(t, "Debian")
	writeFile(t, sb.resolv, "nameserver 10.0.0.10\n")
	if out, rc := sb.run(t, sb.snapshot); rc != 0 {
		t.Fatalf("snapshot rc=%d:\n%s", rc, out)
	}
	sb.mutateLikeTheBlock(t)
	etc := filepath.Dir(sb.resolv)
	if err := os.Chmod(etc, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(etc, 0o755) })

	out, rc := sb.run(t, sb.restore)
	if rc != 1 || !strings.Contains(out, sb.resolv+" restore failed") {
		t.Errorf("restore into a read-only /etc: rc=%d output %q; want rc=1 and %q", rc, out, sb.resolv+" restore failed")
	}
}

// TestFreeipaDNSClientRollback_ELRestoresNetworkManagerSettings drives the
// snapshot and the EL rollback step with a fake nmcli. Its read outputs
// are real ones captured on AlmaLinux 9 vm-targets (NetworkManager
// 1.54.3): `-t -f NAME,DEVICE connection show --active` prints
// "System eth0:eth0" then "lo:lo"; with DHCP DNS, `-g ipv4.dns` and
// `-g ipv4.dns-search` print an empty line and `-g ipv4.ignore-auto-dns`
// prints "no"; with static DNS the lists are comma-separated
// ("192.0.2.1,192.0.2.2", "a.example,b.example") and "yes". Feeding those
// strings back to `nmcli connection modify` restored the same values, and
// "" cleared them, on the same host.
func TestFreeipaDNSClientRollback_ELRestoresNetworkManagerSettings(t *testing.T) {
	cases := []struct {
		name, dns, search, ignore string
	}{
		{"dhcp dns", "", "", "no"},
		{"static dns", "192.0.2.1,192.0.2.2", "a.example,b.example", "yes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sb := newRollbackSandbox(t, "RedHat")
			writeFile(t, sb.resolv, "# Generated by NetworkManager\nnameserver 192.168.122.1\n")
			log := filepath.Join(sb.root, "nmcli.log")
			fake := `#!/bin/bash
{ printf '%s|' "$@"; echo; } >> ` + log + `
case "$*" in
  "-t -f NAME,DEVICE connection show --active") printf 'System eth0:eth0\nlo:lo\n' ;;
  "-g ipv4.dns connection show System eth0") printf '%s\n' '` + tc.dns + `' ;;
  "-g ipv4.dns-search connection show System eth0") printf '%s\n' '` + tc.search + `' ;;
  "-g ipv4.ignore-auto-dns connection show System eth0") printf '%s\n' '` + tc.ignore + `' ;;
esac
`
			if err := os.WriteFile(filepath.Join(sb.bin, "nmcli"), []byte(fake), 0o755); err != nil {
				t.Fatal(err)
			}
			if out, rc := sb.run(t, sb.snapshot); rc != 0 {
				t.Fatalf("snapshot rc=%d:\n%s", rc, out)
			}
			if err := os.Remove(log); err != nil {
				t.Fatal(err)
			}

			out, rc := sb.run(t, sb.restoreNM)
			if rc != 0 {
				t.Fatalf("EL restore rc=%d:\n%s", rc, out)
			}
			calls := strings.Split(strings.TrimSpace(readFile(t, log)), "\n")
			want := []string{
				"connection|modify|System eth0|ipv4.dns|" + tc.dns + "|ipv4.dns-search|" + tc.search + "|ipv4.ignore-auto-dns|" + tc.ignore + "|",
				"device|reapply|eth0|",
			}
			if !reflect.DeepEqual(calls, want) {
				t.Errorf("nmcli calls = %q, want %q", calls, want)
			}
			for _, line := range []string{"connection 'System eth0' DNS settings restored", "device eth0 reapplied"} {
				if !strings.Contains(out, line) {
					t.Errorf("EL restore output missing %q:\n%s", line, out)
				}
			}
		})
	}
}
