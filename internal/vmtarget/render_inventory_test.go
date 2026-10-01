package vmtarget

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/sshcontrol"
)

// TestRenderInventory_AliasesAreGroupsOfTheVM is the regression guard for
// `--hosts dns,ntp,keycloak` at `up` time. The VM is ONE inventory host
// (its Name) and every alias is a single-host child group holding it:
//   - `-l dns`, `hosts: dns` and `groups['dns']` still select the VM;
//   - `hosts: all` runs once, not once per alias, against the same VM;
//   - no alias is also a host name, so Ansible has no "Found both group
//     and host with same name" warning to give (why 7ed605c dropped the
//     groups while aliases were still hosts too);
//   - a v1 spec targeting group `ntp` accepts a VM not named `ntp`.
func TestRenderInventory_AliasesAreGroupsOfTheVM(t *testing.T) {
	tgt := &Target{
		Name:    "core",
		IP:      "192.168.123.232",
		SSHUser: "ubuntu",
		SSHPort: 22,
		KeyPath: "/var/lib/libvirt/images/pilot/core/id_ed25519",
		Hosts:   []string{"core", "dns", "ntp", "keycloak", "dns"},
	}
	inv, err := tgt.RenderInventory()
	if err != nil {
		t.Fatalf("RenderInventory: %v", err)
	}
	if c := strings.Count(inv, "ansible_host: "); c != 1 {
		t.Errorf("want exactly one host entry, got %d:\n%s", c, inv)
	}
	if !strings.Contains(inv, "    core:\n      ansible_connection: ssh") {
		t.Errorf("primary host missing under all.hosts:\n%s", inv)
	}
	for _, alias := range []string{"dns", "ntp", "keycloak"} {
		group := "    " + alias + ":\n      hosts:\n        core: {}\n"
		if strings.Count(inv, group) != 1 {
			t.Errorf("alias %q should be exactly one group holding core:\n%s", alias, inv)
		}
		if strings.Contains(inv, "    "+alias+":\n      ansible_connection") {
			t.Errorf("alias %q must not be a host entry:\n%s", alias, inv)
		}
	}

	list, stderr := ansibleInventoryList(t, inv)
	if strings.Contains(stderr, "Found both group and host") {
		t.Errorf("ansible-inventory warned about a host/group name clash:\n%s", stderr)
	}
	if got := list.hosts(); strings.Join(got, ",") != "core" {
		t.Errorf("inventory hosts = %v, want [core]", got)
	}
	for _, alias := range []string{"dns", "ntp", "keycloak"} {
		if got := list.group(alias); strings.Join(got, ",") != "core" {
			t.Errorf("group %s = %v, want [core]", alias, got)
		}
	}
}

func TestRenderInventory_NoAliasesNoChildren(t *testing.T) {
	tgt := &Target{Name: "solo", IP: "10.0.0.5", SSHUser: "u", SSHPort: 22, KeyPath: "/k", Hosts: []string{"solo"}}
	inv, err := tgt.RenderInventory()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(inv, "children:") {
		t.Errorf("a target without aliases needs no children block:\n%s", inv)
	}
}

// TestRenderInventory_ImplicitGroupAliasesAreSkipped: an alias named after
// one of Ansible's implicit groups would redefine it.
func TestRenderInventory_ImplicitGroupAliasesAreSkipped(t *testing.T) {
	tgt := &Target{Name: "vm", IP: "10.0.0.5", SSHUser: "u", SSHPort: 22, KeyPath: "/k", Hosts: []string{"vm", "all", "ungrouped", "dns"}}
	inv, err := tgt.RenderInventory()
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []string{"all", "ungrouped"} {
		if strings.Contains(inv, "    "+g+":\n") {
			t.Errorf("implicit group %q rendered as an alias:\n%s", g, inv)
		}
	}
	if !strings.Contains(inv, "    dns:\n      hosts:\n        vm: {}\n") {
		t.Errorf("alias dns missing:\n%s", inv)
	}
}

// controlPathRe extracts every ControlPath value from an ssh option string
// or command line.
var controlPathRe = regexp.MustCompile(`ControlPath=("[^"]*"|[^\s'"]+)`)

// TestRenderInventory_PerTargetControlPath: the ControlPath lives in the
// target's own 0700 directory, is set through ansible_ssh_args (which
// Ansible puts first on the ssh command line, and the first value of an
// option is the one OpenSSH uses), and fits a Unix socket.
func TestRenderInventory_PerTargetControlPath(t *testing.T) {
	created := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	tgt := &Target{Name: strings.Repeat("n", 128), IP: "10.0.0.5", SSHUser: "u", SSHPort: 22, KeyPath: "/k", CreatedAt: created}
	inv, err := tgt.RenderInventory()
	if err != nil {
		t.Fatal(err)
	}
	dir := tgt.ControlDir()
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("control directory %s: %v %v, want a 0700 directory", dir, info, err)
	}
	var sshArgs, commonArgs string
	for _, line := range strings.Split(inv, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "ansible_ssh_args: "); ok {
			sshArgs = v
		}
		if v, ok := strings.CutPrefix(line, "ansible_ssh_common_args: "); ok {
			commonArgs = v
		}
	}
	paths := controlPathRe.FindAllStringSubmatch(sshArgs, -1)
	if len(paths) != 1 || strings.Trim(paths[0][1], `"`) != filepath.Join(dir, "%C") {
		t.Fatalf("ansible_ssh_args %q should set ControlPath %s/%%C", sshArgs, dir)
	}
	if strings.Contains(commonArgs, "Control") {
		t.Errorf("ansible_ssh_common_args %q should not carry control options (ssh_args wins)", commonArgs)
	}

	// Socket budget: the ControlPath with %C expanded (40 hex) plus the
	// ".<16 chars>" suffix ssh binds first must fit sun_path (108 bytes
	// including NUL), whatever the target name, under the production base.
	t.Setenv(sshcontrol.BaseEnv, "")
	expanded := filepath.Join(tgt.ControlDir(), strings.Repeat("0", 40))
	if budget := 108 - 1 - len(".0123456789abcdef"); len(expanded) > budget {
		t.Fatalf("expanded ControlPath is %d bytes, over the %d-byte budget: %s", len(expanded), budget, expanded)
	}
}

func TestControlDir_PerTargetInstance(t *testing.T) {
	at := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	a := &Target{Name: "vb-1", CreatedAt: at}
	same := &Target{Name: "vb-1", CreatedAt: at}
	recreated := &Target{Name: "vb-1", CreatedAt: at.Add(time.Second)}
	other := &Target{Name: "vb-2", CreatedAt: at}
	if a.ControlDir() != same.ControlDir() {
		t.Errorf("the same target got two control directories")
	}
	if a.ControlDir() == recreated.ControlDir() {
		t.Errorf("a VM recreated under the same name reuses the old control directory %s", a.ControlDir())
	}
	if a.ControlDir() == other.ControlDir() {
		t.Errorf("two targets share the control directory %s", a.ControlDir())
	}
}

func TestRenderGroupedInventory_PerTargetControlPaths(t *testing.T) {
	at := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	a := &Target{Name: "vb-a", IP: "10.0.0.5", SSHUser: "u", SSHPort: 22, KeyPath: "/ka", CreatedAt: at}
	b := &Target{Name: "vb-b", IP: "10.0.0.6", SSHUser: "u", SSHPort: 22, KeyPath: "/kb", CreatedAt: at}
	inv, err := RenderGroupedInventory(map[string]*Target{"vb-a": a, "vb-b": b}, []string{"g"}, map[string][]string{"g": {"vb-a", "vb-b"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tgt := range []*Target{a, b} {
		if !strings.Contains(inv, filepath.Join(tgt.ControlDir(), "%C")) {
			t.Errorf("%s's ControlPath missing:\n%s", tgt.Name, inv)
		}
		if _, err := os.Stat(tgt.ControlDir()); err != nil {
			t.Errorf("%s's control directory was not created: %v", tgt.Name, err)
		}
	}
	if strings.Contains(inv, "~/.ansible/cp") {
		t.Errorf("grouped inventory still uses the shared ControlPath:\n%s", inv)
	}
}

// TestRenderInventory_ControlPathWinsOnTheSSHCommandLine runs real Ansible
// with the repo ansible.cfg (whose ssh_args set the shared
// ~/.ansible/cp/pilot-%C) against an unroutable address and reads the ssh
// command line from -vvv: the first ControlPath must be the target's own.
func TestRenderInventory_ControlPathWinsOnTheSSHCommandLine(t *testing.T) {
	if _, err := exec.LookPath("ansible"); err != nil {
		t.Skip("ansible not installed")
	}
	cfg, err := filepath.Abs(filepath.Join("..", "..", "ansible.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	tgt := &Target{Name: "vb-cp", IP: "192.0.2.1", SSHUser: "u", SSHPort: 22, KeyPath: "/nonexistent", CreatedAt: time.Now()}
	inv, err := tgt.RenderInventory()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	invPath := filepath.Join(dir, "inv.yml")
	if err := os.WriteFile(invPath, []byte(inv), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible", "vb-cp", "-i", invPath, "-m", "ansible.builtin.ping", "-vvv")
	cmd.Env = append(os.Environ(),
		"ANSIBLE_CONFIG="+cfg,
		"ANSIBLE_TIMEOUT=1",
		"ANSIBLE_HOME="+filepath.Join(dir, "home"),
		"ANSIBLE_LOCAL_TEMP="+filepath.Join(dir, "tmp"),
		"ANSIBLE_CACHE_PLUGIN=memory",
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	_ = cmd.Run() // unreachable by design
	var sshLine string
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.Contains(line, "SSH: EXEC ssh") {
			sshLine = line
			break
		}
	}
	if sshLine == "" {
		t.Fatalf("no ssh command line in ansible -vvv output:\n%s", out.String())
	}
	paths := controlPathRe.FindAllStringSubmatch(sshLine, -1)
	if len(paths) == 0 {
		t.Fatalf("no ControlPath on the ssh command line: %s", sshLine)
	}
	if got, want := strings.Trim(paths[0][1], `"`), filepath.Join(tgt.ControlDir(), "%C"); got != want {
		t.Fatalf("first ControlPath on the ssh command line is %q, want %q\n%s", got, want, sshLine)
	}
	if strings.Contains(sshLine, ".ansible/cp") {
		t.Errorf("the shared ControlPath from ansible.cfg is still on the command line: %s", sshLine)
	}
}

type inventoryList map[string]json.RawMessage

func (l inventoryList) hosts() []string {
	var meta struct {
		HostVars map[string]json.RawMessage `json:"hostvars"`
	}
	_ = json.Unmarshal(l["_meta"], &meta)
	var out []string
	for h := range meta.HostVars {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func (l inventoryList) group(name string) []string {
	var g struct {
		Hosts []string `json:"hosts"`
	}
	_ = json.Unmarshal(l[name], &g)
	sort.Strings(g.Hosts)
	return g.Hosts
}

// ansibleInventoryList parses inv with the real ansible-inventory.
func ansibleInventoryList(t *testing.T, inv string) (inventoryList, string) {
	t.Helper()
	if _, err := exec.LookPath("ansible-inventory"); err != nil {
		t.Skip("ansible-inventory not installed")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "inv.yml")
	if err := os.WriteFile(path, []byte(inv), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-inventory", "-i", path, "--list")
	cmd.Env = append(os.Environ(), "ANSIBLE_HOME="+filepath.Join(dir, "home"), "ANSIBLE_LOCAL_TEMP="+filepath.Join(dir, "tmp"))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("ansible-inventory: %v\n%s", err, stderr.String())
	}
	var list inventoryList
	if err := json.Unmarshal(stdout.Bytes(), &list); err != nil {
		t.Fatalf("parse ansible-inventory --list: %v\n%s", err, stdout.String())
	}
	return list, stderr.String()
}
