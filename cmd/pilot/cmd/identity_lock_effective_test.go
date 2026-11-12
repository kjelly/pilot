package cmd

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/sshdial"
)

// Issue #319: the identity lock must protect the host ansible-playbook is going
// to operate on, with the connection settings it is going to use. Ansible layers
// extra vars (-e key=value, JSON, @file) over the inventory, and the inventory
// over the connection settings of ansible.cfg and the ANSIBLE_* environment; the
// lock used to read the inventory alone, so a `-e @file` that set ansible_host
// locked host A while the playbook ran on host B.
//
// These tests run the production derivation (identityLockTarget) with the real
// ansible-inventory, ansible and ansible-config on real inventories, vars files,
// ansible.cfg files and environments; nothing connects anywhere. Each case that
// must be refused has a twin that must be accepted (AGENTS.md §5.12), and every
// accepted target is compared with what Ansible itself reports for the same
// arguments, so the test does not agree with the code by construction.

// effectiveInventory has two groups so that target_group can point the playbook
// at a host the lock was not asked about.
const effectiveInventory = `all:
  children:
    freeipa-server:
      hosts:
        ipa-1:
          ansible_host: 192.0.2.10
          ansible_user: root
    other:
      hosts:
        ipa-2:
          ansible_host: 192.0.2.30
          ansible_user: root
`

// noUserInventory leaves ansible_user unset so ansible.cfg's remote_user shows.
const noUserInventory = `all:
  children:
    freeipa-server:
      hosts:
        ipa-1:
          ansible_host: 192.0.2.10
`

// writeEffectiveInventory is writeLockInventory with another inventory body: the
// same tool checks, ansible home and configuration isolation.
func writeEffectiveInventory(t *testing.T, body string) string {
	t.Helper()
	inv := writeLockInventory(t, "")
	if err := os.WriteFile(inv, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return inv
}

func writeVarsFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "extra.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func lockTargetFor(t *testing.T, inv string, hosts []string, extraArgs ...string) (string, sshdial.Target, error) {
	t.Helper()
	return identityLockTarget(context.Background(), identityLockRequest{Inventory: inv, Hosts: hosts, ExtraArgs: extraArgs})
}

// ansibleHostVar is what Ansible itself says host's variable key is with args:
// the oracle the lock's answer is compared with.
func ansibleHostVar(t *testing.T, inv, host, key string, args ...string) any {
	t.Helper()
	out, err := exec.Command("ansible-inventory", append([]string{"-i", inv, "--list"}, args...)...).Output()
	if err != nil {
		t.Fatalf("ansible-inventory: %v", err)
	}
	var doc struct {
		Meta struct {
			Hostvars map[string]map[string]any `json:"hostvars"`
		} `json:"_meta"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Meta.Hostvars[host][key]
}

// The reproduction of #319 and its fix: extra vars in each form Ansible takes
// move the playbook to another address, port and user; the lock follows them.
func TestIdentityLockTargetFollowsTheVariablesThePlaybookWillSee(t *testing.T) {
	file := func(body string) []string { return []string{"-e", "@" + writeVarsFile(t, body)} }
	for _, tc := range []struct {
		name     string
		args     []string
		wantHost string
		wantPort int
		wantUser string
	}{
		{"the inventory alone", nil, "192.0.2.10", 0, "root"},
		{"-e @file overrides ansible_host, ansible_port and ansible_user",
			file("ansible_host: 192.0.2.99\nansible_port: 2222\nansible_user: ops\n"), "192.0.2.99", 2222, "ops"},
		{"-e key=value overrides ansible_host", []string{"-e", "ansible_host=192.0.2.77"}, "192.0.2.77", 0, "root"},
		{"-e JSON overrides ansible_port", []string{"-e", `{"ansible_port": 2200}`}, "192.0.2.10", 2200, "root"},
		{"a later -e wins over an earlier one",
			append(file("ansible_host: 192.0.2.98\n"), "-e", "ansible_host=192.0.2.97"), "192.0.2.97", 0, "root"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv := writeEffectiveInventory(t, effectiveInventory)
			host, target, err := lockTargetFor(t, inv, nil, tc.args...)
			if err != nil {
				t.Fatal(err)
			}
			if host != "ipa-1" {
				t.Fatalf("host = %q: the host is the inventory name, never the address (AGENTS.md §5.13)", host)
			}
			if target.Host != tc.wantHost || target.Port != tc.wantPort || target.User != tc.wantUser {
				t.Fatalf("target = %+v, want host %s port %d user %s", target, tc.wantHost, tc.wantPort, tc.wantUser)
			}
			if oracle := ansibleHostVar(t, inv, "ipa-1", "ansible_host", tc.args...); oracle != tc.wantHost {
				t.Fatalf("Ansible reports ansible_host %v for the same arguments, the lock took %s", oracle, tc.wantHost)
			}
		})
	}

	// What the old derivation saw, so that this test fails if the lock goes back
	// to reading the inventory alone: the same file, with no ExtraArgs, still
	// says 192.0.2.10 while the playbook would be sent to 192.0.2.99.
	t.Run("without the arguments the lock would have been on the wrong host", func(t *testing.T) {
		inv := writeEffectiveInventory(t, effectiveInventory)
		args := file("ansible_host: 192.0.2.99\n")
		_, target, err := lockTargetFor(t, inv, nil)
		if err != nil {
			t.Fatal(err)
		}
		if target.Host != "192.0.2.10" {
			t.Fatalf("the inventory alone gave %s", target.Host)
		}
		if oracle := ansibleHostVar(t, inv, "ipa-1", "ansible_host", args...); oracle == target.Host {
			t.Fatal("the override does not change what Ansible sees: this test shows nothing")
		}
	})
}

// A connection setting that only arrives through extra vars is judged like the
// same setting in the inventory: refused when pilot's ssh cannot honor it, with
// the variable named, and accepted in the supported form.
func TestIdentityLockTargetRefusesUnsupportedExtraVars(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		wantIn string
	}{
		{"ProxyCommand", "ansible_ssh_extra_args: \"-o ProxyCommand='nc %h %p'\"\n", "ProxyCommand"},
		{"a docker connection", "ansible_connection: docker\n", "ansible_connection 是 docker"},
		{"a connection password", "ansible_ssh_pass: sentinel-not-a-credential\n", "設定了 ansible_ssh_pass"},
		{"an option outside the allowlist", "ansible_ssh_common_args: \"-o ForwardAgent=yes\"\n", "ForwardAgent"},
		{"the ssh executable", "ansible_ssh_executable: /usr/local/bin/other-ssh\n", "設定了 ansible_ssh_executable"},
		{"a port that is not a number", "ansible_port: not-a-port\n", "ansible_port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv := writeEffectiveInventory(t, effectiveInventory)
			_, _, err := lockTargetFor(t, inv, nil, "-e", "@"+writeVarsFile(t, tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.wantIn) {
				t.Fatalf("err = %v, want it to hold %q", err, tc.wantIn)
			}
			if strings.Contains(err.Error(), "sentinel-not-a-credential") {
				t.Fatalf("the refusal shows a password: %v", err)
			}
			// The inventory alone passes: it is the extra var that is refused.
			if _, _, err := lockTargetFor(t, inv, nil); err != nil {
				t.Fatalf("the inventory without the extra var was refused: %v", err)
			}
		})
	}

	t.Run("a supported extra var is accepted", func(t *testing.T) {
		inv := writeEffectiveInventory(t, effectiveInventory)
		body := "ansible_ssh_common_args: \"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null\"\n"
		_, target, err := lockTargetFor(t, inv, nil, "-e", "@"+writeVarsFile(t, body))
		if err != nil {
			t.Fatal(err)
		}
		if target.Options["StrictHostKeyChecking"] != "no" {
			t.Fatalf("options = %v", target.Options)
		}
	})
}

// What decides the playbook's hosts: is target_group. It can come through
// -e @file as well as -e key=value, and the lock must be on a host the playbook
// will run on.
func TestIdentityLockTargetAgreesWithTheHostsThePlaybookRunsOn(t *testing.T) {
	const wrongGroup = "target_group: other\n"
	t.Run("a run handed a host the playbook will not reach is refused", func(t *testing.T) {
		inv := writeEffectiveInventory(t, effectiveInventory)
		for name, args := range map[string][]string{
			"-e @file":     {"-e", "@" + writeVarsFile(t, wrongGroup)},
			"-e key=value": {"-e", "target_group=other"},
			"-e JSON":      {"-e", `{"target_group": "other"}`},
		} {
			t.Run(name, func(t *testing.T) {
				_, _, err := lockTargetFor(t, inv, []string{"ipa-1"}, args...)
				if err == nil {
					t.Fatal("the lock was derived for ipa-1 while the playbook runs on the `other` group")
				}
				for _, want := range []string{"鎖與 playbook 的目標會不同台", "ipa-1", "other", "ipa-2"} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("err = %v, want it to hold %q", err, want)
					}
				}
			})
		}
	})

	t.Run("the same host is accepted when target_group reaches it", func(t *testing.T) {
		inv := writeEffectiveInventory(t, effectiveInventory)
		host, _, err := lockTargetFor(t, inv, []string{"ipa-1"}, "-e", "target_group=freeipa-server")
		if err != nil || host != "ipa-1" {
			t.Fatalf("host = %q, err = %v", host, err)
		}
		host, target, err := lockTargetFor(t, inv, []string{"ipa-2"}, "-e", "target_group=other")
		if err != nil || host != "ipa-2" || target.Host != "192.0.2.30" {
			t.Fatalf("host = %q, target = %+v, err = %v", host, target, err)
		}
	})

	t.Run("a run that resolves its own host follows target_group", func(t *testing.T) {
		inv := writeEffectiveInventory(t, effectiveInventory)
		host, target, err := lockTargetFor(t, inv, nil, "-e", "@"+writeVarsFile(t, wrongGroup))
		if err != nil {
			t.Fatal(err)
		}
		if host != "ipa-2" || target.Host != "192.0.2.30" {
			t.Fatalf("host = %q, target = %+v: the playbook runs on `other`, which is ipa-2", host, target)
		}
	})

	t.Run("a group with more than one host is not one server", func(t *testing.T) {
		inv := writeEffectiveInventory(t, effectiveInventory)
		_, _, err := lockTargetFor(t, inv, nil, "-e", "target_group=all")
		if err == nil || !strings.Contains(err.Error(), "剛好一台 freeipa-server") {
			t.Fatalf("err = %v, want the exactly-one refusal", err)
		}
	})

	t.Run("a target_group that is no plain pattern is refused", func(t *testing.T) {
		inv := writeEffectiveInventory(t, effectiveInventory)
		for name, args := range map[string][]string{
			"an option": {"-e", "target_group=--module-path=/tmp"},
			"empty":     {"-e", `{"target_group": ""}`},
			"a number":  {"-e", `{"target_group": 7}`},
			"a list":    {"-e", `{"target_group": ["other"]}`},
		} {
			t.Run(name, func(t *testing.T) {
				if _, _, err := lockTargetFor(t, inv, nil, args...); err == nil {
					t.Fatal("accepted")
				}
			})
		}
	})
}

// The tests above call identityLockTarget, the derivation. What takes the lock is
// productionIdentityLock, whose acquirer builds the derivation's request from its
// own: an acquirer that dropped req.ExtraArgs (#319 reopened at the last hop)
// leaves every test above green, because none of them goes through it. This one
// starts the real acquirer with the real ansible tools, only the ssh program
// replaced, and reads where the lock was dialed: the target the dialer was built
// for and the destination of the ssh process the stand-in logged. What it
// expects is what the fixture file says and what Ansible itself reports for the
// same arguments, not a second call of the code under test. The rows without
// arguments dial the inventory's own address, so an acquirer that ignores the
// arguments and one that honors them cannot both pass.
func TestProductionIdentityLockDialsWhatTheExtraArgsSay(t *testing.T) {
	file := func(body string) []string { return []string{"-e", "@" + writeVarsFile(t, body)} }
	const overrides = "ansible_host: 192.0.2.99\nansible_port: 2222\nansible_user: ops\n"
	for _, tc := range []struct {
		name     string
		args     []string
		hosts    []string // what the funnel hands over; nil asks the acquirer to resolve them
		wantHost string   // the inventory name that is locked
		wantAddr string
		wantUser string
		wantPort int
	}{
		{"no extra arguments, hosts left to the acquirer (access, decommission)", nil, nil, "ipa-1", "192.0.2.10", "root", 0},
		{"no extra arguments, hosts handed over (deploy runner)", nil, []string{"ipa-1"}, "ipa-1", "192.0.2.10", "root", 0},
		{"-e @file overrides address, port and user, hosts handed over", file(overrides), []string{"ipa-1"}, "ipa-1", "192.0.2.99", "ops", 2222},
		{"-e @file overrides address, port and user, hosts left to the acquirer", file(overrides), nil, "ipa-1", "192.0.2.99", "ops", 2222},
		{"-e key=value overrides the address", []string{"-e", "ansible_host=192.0.2.77"}, []string{"ipa-1"}, "ipa-1", "192.0.2.77", "root", 0},
		{"-e @file target_group moves the play, hosts left to the acquirer", file("target_group: other\n"), nil, "ipa-2", "192.0.2.30", "root", 0},
		{"-e @file target_group moves the play, the host it reaches handed over", file("target_group: other\n"), []string{"ipa-2"}, "ipa-2", "192.0.2.30", "root", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv := writeEffectiveInventory(t, effectiveInventory)
			seam := useLocalLockDialer(t)
			held, err := productionIdentityLock(identityLockRequest{Inventory: inv, Hosts: tc.hosts, ExtraArgs: tc.args})(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = held.Release() }()
			if held.Host != tc.wantHost {
				t.Fatalf("the lock is on %q, want %q", held.Host, tc.wantHost)
			}
			targets := seam.started()
			if len(targets) != 1 {
				t.Fatalf("started %d ssh dialers, want 1", len(targets))
			}
			if got := targets[0]; got.Host != tc.wantAddr || got.Port != tc.wantPort || got.User != tc.wantUser {
				t.Fatalf("the acquirer dialed %+v, want %s port %d user %s", got, tc.wantAddr, tc.wantPort, tc.wantUser)
			}
			destinations := seam.sshDestinations(t)
			if len(destinations) == 0 {
				t.Fatal("no ssh process was started for the lock")
			}
			for _, destination := range destinations {
				if destination != tc.wantAddr {
					t.Fatalf("ssh was started for %q, want %s (all of %q)", destination, tc.wantAddr, destinations)
				}
			}
			if oracle := ansibleHostVar(t, inv, tc.wantHost, "ansible_host", tc.args...); oracle != tc.wantAddr {
				t.Fatalf("Ansible reports ansible_host %v for the same arguments, the test expects %s", oracle, tc.wantAddr)
			}
		})
	}

	// The refusals the arguments cause happen at the acquirer too, and nothing is
	// dialed; the same request without the argument is accepted.
	for _, tc := range []struct {
		name   string
		args   []string
		wantIn []string
	}{
		{"a run handed a host the extra vars' target_group does not reach", file("target_group: other\n"), []string{"鎖與 playbook 的目標會不同台", "ipa-1", "other", "ipa-2"}},
		{"a connection setting only the extra vars carry", file("ansible_ssh_extra_args: \"-o ProxyCommand='nc %h %p'\"\n"), []string{"ProxyCommand"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv := writeEffectiveInventory(t, effectiveInventory)
			seam := useLocalLockDialer(t)
			request := identityLockRequest{Inventory: inv, Hosts: []string{"ipa-1"}, ExtraArgs: tc.args}
			_, err := productionIdentityLock(request)(context.Background())
			if err == nil {
				t.Fatal("the lock was taken although the playbook's arguments make it the wrong one")
			}
			for _, want := range tc.wantIn {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("err = %v, want it to hold %q", err, want)
				}
			}
			if got := seam.started(); len(got) != 0 {
				t.Fatalf("an ssh dialer was built for a refused lock: %+v", got)
			}
			if got := seam.sshDestinations(t); len(got) != 0 {
				t.Fatalf("an ssh process was started for a refused lock: %q", got)
			}
			request.ExtraArgs = nil
			held, err := productionIdentityLock(request)(context.Background())
			if err != nil {
				t.Fatalf("without the argument the same request was refused: %v", err)
			}
			defer func() { _ = held.Release() }()
			if got := seam.started(); len(got) != 1 || got[0].Host != "192.0.2.10" {
				t.Fatalf("the unrefused request dialed %+v, want the inventory's 192.0.2.10", got)
			}
		})
	}
}

// The extra-vars layer alone decides target_group (loadEffectiveTargetGroup reads
// it with ansible-inventory; this is what is made of what it printed): the
// default when none sets it, the value when one does, an error when the value
// is not a plain host pattern.
func TestTargetGroupFromExtraVars(t *testing.T) {
	for _, tc := range []struct {
		name    string
		vars    map[string]any
		want    string
		wantErr string
	}{
		{"unset", map[string]any{"x": 1}, identityDefaultTargetGroup, ""},
		{"no extra vars", nil, identityDefaultTargetGroup, ""},
		{"nil is unset", map[string]any{"target_group": nil}, identityDefaultTargetGroup, ""},
		{"a value", map[string]any{"target_group": "g"}, "g", ""},
		{"a value with blanks around it", map[string]any{"target_group": " g "}, "g", ""},
		{"not a string", map[string]any{"target_group": 3.0}, "", "非空的字串"},
		{"a list", map[string]any{"target_group": []any{"g"}}, "", "非空的字串"},
		{"blank", map[string]any{"target_group": "  "}, "", "非空的字串"},
		{"an option", map[string]any{"target_group": "-m"}, "", "以 - 開頭"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := targetGroupFromExtraVars(tc.vars)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v, want %q", got, err, tc.want)
			}
		})
	}
}

// identityPlaybookPath is the real identity apply playbook of the repo.
func identityPlaybookPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRootForTest(t), deployIdentityPlaybook)
}

// identityPlaybookHosts is what ansible-playbook itself says the hosts of
// freeipa-identity-apply.yml's play are for inv and args: --list-hosts evaluates
// the real playbook's `hosts:` line and runs nothing (ansible-core 2.19.2). It is
// the oracle the lock's answer is compared with: the lock must be taken on the
// host this lists, whatever the lock's own reading of the variables says.
func identityPlaybookHosts(t *testing.T, playbook, inv string, args ...string) []string {
	t.Helper()
	out, err := exec.Command("ansible-playbook", append([]string{"-i", inv, playbook, "--list-hosts"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("ansible-playbook --list-hosts: %v\n%s", err, out)
	}
	var hosts []string
	listing := false
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "hosts ("):
			listing = true
		case listing && strings.HasPrefix(line, "      ") && trimmed != "":
			hosts = append(hosts, trimmed)
		default:
			listing = false
		}
	}
	return hosts
}

// A target_group that only the inventory sets (under `all: vars:`, in one host's
// variables, or in group_vars next to the inventory) is on every host in
// ansible-inventory's listing, but the play's `hosts:` is templated with the
// extra vars alone: the playbook still runs on freeipa-server. The lock followed
// the listing and was taken on the `other` host while the playbook ran on ipa-1
// (the failure of issue #319 turned around), and a deploy that handed it ipa-1
// was refused although the playbook runs there. The oracle is ansible-playbook's
// own --list-hosts for the real playbook.
func TestInventoryLevelTargetGroupDoesNotRetargetTheLock(t *testing.T) {
	const withAllVars = `all:
  vars:
    target_group: other
  children:
    freeipa-server:
      hosts:
        ipa-1:
          ansible_host: 192.0.2.10
          ansible_user: root
    other:
      hosts:
        ipa-2:
          ansible_host: 192.0.2.30
          ansible_user: root
`
	const withHostVars = `all:
  children:
    freeipa-server:
      hosts:
        ipa-1:
          ansible_host: 192.0.2.10
          ansible_user: root
          target_group: other
    other:
      hosts:
        ipa-2:
          ansible_host: 192.0.2.30
          ansible_user: root
`
	for _, tc := range []struct {
		name      string
		inventory string
		// groupVars is a group_vars/all.yml next to the inventory, if not "".
		groupVars string
	}{
		{"all: vars:", withAllVars, ""},
		{"one host's variables", withHostVars, ""},
		{"group_vars/all.yml next to the inventory", effectiveInventory, "target_group: other\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv := writeEffectiveInventory(t, tc.inventory)
			if tc.groupVars != "" {
				dir := filepath.Join(filepath.Dir(inv), "group_vars")
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "all.yml"), []byte(tc.groupVars), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			playbook := identityPlaybookPath(t)
			// What makes this test show something: the inventory does say `other`
			// on the hosts, and the playbook does not follow it.
			if got := ansibleHostVar(t, inv, "ipa-1", "target_group"); got != "other" {
				t.Fatalf("the inventory does not set target_group on ipa-1 (%v): this test shows nothing", got)
			}
			if want := []string{"ipa-1"}; !reflect.DeepEqual(identityPlaybookHosts(t, playbook, inv), want) {
				t.Fatalf("ansible-playbook runs on %v, want %v: the premise of this test is wrong", identityPlaybookHosts(t, playbook, inv), want)
			}

			for _, args := range [][]string{
				// No extra arguments: the default, and no extra call to Ansible.
				nil,
				// Some: target_group is read from them (and from them alone).
				{"-e", "@" + writeVarsFile(t, "stage: sandbox\n")},
			} {
				// A run that resolves its own host (access, decommission): the host
				// the playbook runs on.
				host, target, err := lockTargetFor(t, inv, nil, args...)
				if err != nil {
					t.Fatalf("args %q: %v", args, err)
				}
				if oracle := identityPlaybookHosts(t, playbook, inv, args...); !reflect.DeepEqual(oracle, []string{host}) {
					t.Fatalf("args %q: the lock is on %s, ansible-playbook runs on %v", args, host, oracle)
				}
				if host != "ipa-1" || target.Host != "192.0.2.10" {
					t.Fatalf("args %q: host = %q, target = %+v, want ipa-1", args, host, target)
				}
				// A run handed ipa-1 (the deploy runner): accepted.
				if host, _, err := lockTargetFor(t, inv, []string{"ipa-1"}, args...); err != nil || host != "ipa-1" {
					t.Fatalf("args %q: handed ipa-1: host = %q, err = %v", args, host, err)
				}
			}

			// An extra var does retarget the play, and the lock follows it: the
			// same inventory, `-e target_group=…`, in both directions (once: the
			// source of the inventory-level value does not matter to this).
			if tc.name == "all: vars:" {
				for group, want := range map[string]string{"freeipa-server": "ipa-1", "other": "ipa-2"} {
					args := []string{"-e", "target_group=" + group}
					host, _, err := lockTargetFor(t, inv, nil, args...)
					if err != nil {
						t.Fatalf("args %q: %v", args, err)
					}
					if oracle := identityPlaybookHosts(t, playbook, inv, args...); !reflect.DeepEqual(oracle, []string{want}) || host != want {
						t.Fatalf("args %q: the lock is on %s, ansible-playbook runs on %v, want %s", args, host, oracle, want)
					}
				}
			}
			// Both at once: the inventory says `other`, the extra var says
			// freeipa-server, and the extra var is what the play sees.
			host, _, err := lockTargetFor(t, inv, []string{"ipa-1"}, "-e", "@"+writeVarsFile(t, "target_group: freeipa-server\n"))
			if err != nil || host != "ipa-1" {
				t.Fatalf("inventory says other, -e @file says freeipa-server: host = %q, err = %v", host, err)
			}
		})
	}
}

// The extra vars are read through an inline one-host inventory, and the working
// directory of a pilot run is a workspace: it has group_vars/ and host_vars/ of
// its own, which Ansible applies to an inline inventory too. They are not the
// extra vars, and must not be read as them (checked with ansible-inventory
// itself: without the isolation the host `localhost` carries the cwd's
// target_group).
func TestExtraVarsTargetGroupIgnoresTheWorkingDirectoryVars(t *testing.T) {
	inv := writeEffectiveInventory(t, effectiveInventory)
	playbook := identityPlaybookPath(t)
	cwd := t.TempDir()
	for name, body := range map[string]string{
		"group_vars/all.yml":       "target_group: other\n",
		"group_vars/ungrouped.yml": "target_group: other\n",
		"host_vars/localhost.yml":  "target_group: other\n",
	} {
		path := filepath.Join(cwd, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(cwd)
	// The premise: an inline inventory in this directory does see the files.
	if got := ansibleHostVar(t, "localhost,", "localhost", "target_group", "-e", "x=1"); got != "other" {
		t.Skipf("this Ansible does not apply the working directory's group_vars to an inline inventory (target_group = %v): nothing to isolate", got)
	}

	args := []string{"-e", "stage=sandbox"}
	group, err := loadEffectiveTargetGroup(context.Background(), args)
	if err != nil || group != identityDefaultTargetGroup {
		t.Fatalf("target_group = %q, err = %v: the working directory's group_vars were read as extra vars", group, err)
	}
	host, _, err := lockTargetFor(t, inv, nil, args...)
	if err != nil || host != "ipa-1" {
		t.Fatalf("host = %q, err = %v, want ipa-1", host, err)
	}
	if oracle := identityPlaybookHosts(t, playbook, inv, args...); !reflect.DeepEqual(oracle, []string{"ipa-1"}) {
		t.Fatalf("ansible-playbook runs on %v", oracle)
	}
	// The twin: an extra var in the same directory is still read.
	if group, err := loadEffectiveTargetGroup(context.Background(), []string{"-e", "target_group=g"}); err != nil || group != "g" {
		t.Fatalf("target_group = %q, err = %v, want the extra var's g", group, err)
	}
}

// The extra vars are read in the environment of the run, and an environment that
// restricts the inventory plugins must not make the inline host list unreadable:
// a listing without the host would have read as "no target_group".
func TestExtraVarsTargetGroupIsReadWhateverTheEnvironmentEnables(t *testing.T) {
	inv := writeEffectiveInventory(t, effectiveInventory)
	t.Setenv("ANSIBLE_INVENTORY_ENABLED", "yaml")
	host, _, err := lockTargetFor(t, inv, nil, "-e", "target_group=other")
	if err != nil || host != "ipa-2" {
		t.Fatalf("host = %q, err = %v, want ipa-2 (the extra var's group)", host, err)
	}
}

// With no -e or vault argument target_group is the default and Ansible is not
// asked about it: the run that is handed its hosts costs no ansible call beyond
// the inventory listing.
func TestEffectiveTargetGroupAsksNoAnsibleWithoutArguments(t *testing.T) {
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "called")
	script := "#!/bin/sh\ntouch '" + marker + "'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "ansible-inventory"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	group, err := loadEffectiveTargetGroup(context.Background(), nil)
	if err != nil || group != identityDefaultTargetGroup {
		t.Fatalf("group = %q, err = %v", group, err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("ansible-inventory was run for a lock with no extra arguments")
	}
	// The same fake with arguments is asked and its failure refuses.
	if _, err := loadEffectiveTargetGroup(context.Background(), []string{"-e", "x=1"}); err == nil {
		t.Fatal("a failing ansible-inventory did not refuse")
	}
	if _, statErr := os.Stat(marker); statErr != nil {
		t.Fatal("ansible-inventory was not run for a lock with extra arguments")
	}
}

// The connection settings of ansible.cfg and the environment are what the
// playbook connects with when neither the host nor an extra var says otherwise.
func TestIdentityLockTargetReadsAnsibleConfigConnectionSettings(t *testing.T) {
	const multiplex = "-o ControlMaster=auto -o ControlPersist=60s"
	for _, tc := range []struct {
		name      string
		inventory string
		cfg       string
		env       map[string]string
		check     func(t *testing.T, target sshdial.Target)
		wantIn    string
	}{
		{name: "the repo's own settings change nothing", inventory: effectiveInventory,
			cfg: "[defaults]\nhost_key_checking = False\ntimeout = 30\n[ssh_connection]\npipelining = true\nssh_args = " + multiplex + "\n",
			check: func(t *testing.T, target sshdial.Target) {
				if target.Host != "192.0.2.10" || target.User != "root" || len(target.Options) != 0 {
					t.Fatalf("target = %+v", target)
				}
			}},
		{name: "the runtime's ANSIBLE_SSH_ARGS (multiplexing only) is accepted", inventory: effectiveInventory,
			env:   map[string]string{"ANSIBLE_SSH_ARGS": "-o ControlMaster=auto -o ControlPath=\"/tmp/cp-%C\" -o ControlPersist=60s"},
			check: func(t *testing.T, target sshdial.Target) {}},
		{name: "ProxyCommand in ansible.cfg's ssh_args", inventory: effectiveInventory,
			cfg:    "[ssh_connection]\nssh_args = -o ProxyCommand=\"ssh -W %h:%p jump\" -o ControlMaster=auto\n",
			wantIn: "ansible_ssh_args"},
		{name: "ProxyCommand in ANSIBLE_SSH_ARGS", inventory: effectiveInventory,
			env:    map[string]string{"ANSIBLE_SSH_ARGS": "-o ProxyCommand=\"ssh -W %h:%p jump\""},
			wantIn: "env: ANSIBLE_SSH_ARGS"},
		{name: "ProxyCommand in ansible.cfg's ssh_extra_args", inventory: effectiveInventory,
			cfg:    "[ssh_connection]\nssh_extra_args = -o ProxyCommand=\"nc %h %p\"\n",
			wantIn: "ProxyCommand"},
		{name: "ANSIBLE_SSH_EXECUTABLE", inventory: effectiveInventory,
			env: map[string]string{"ANSIBLE_SSH_EXECUTABLE": "/usr/local/bin/other-ssh"}, wantIn: "env: ANSIBLE_SSH_EXECUTABLE"},
		{name: "a transport that is not ssh", inventory: effectiveInventory,
			env: map[string]string{"ANSIBLE_TRANSPORT": "local"}, wantIn: "ansible_connection 是 local"},
		{name: "ask_pass", inventory: effectiveInventory,
			env: map[string]string{"ANSIBLE_ASK_PASS": "true"}, wantIn: "ask_pass"},
		{name: "ProxyJump in ssh_common_args is carried to the lock's ssh", inventory: effectiveInventory,
			cfg: "[ssh_connection]\nssh_common_args = -o ProxyJump=bastion\n",
			check: func(t *testing.T, target sshdial.Target) {
				if target.Options["ProxyJump"] != "bastion" {
					t.Fatalf("options = %v", target.Options)
				}
			}},
		{name: "remote_user is the user when the host sets none", inventory: noUserInventory,
			cfg: "[defaults]\nremote_user = ops\n",
			check: func(t *testing.T, target sshdial.Target) {
				if target.User != "ops" {
					t.Fatalf("user = %q", target.User)
				}
			}},
		{name: "the host's ansible_user wins over remote_user", inventory: effectiveInventory,
			cfg: "[defaults]\nremote_user = ops\n",
			check: func(t *testing.T, target sshdial.Target) {
				if target.User != "root" {
					t.Fatalf("user = %q", target.User)
				}
			}},
		{name: "remote_port is the port when the host sets none", inventory: effectiveInventory,
			env: map[string]string{"ANSIBLE_REMOTE_PORT": "2201"},
			check: func(t *testing.T, target sshdial.Target) {
				if target.Port != 2201 {
					t.Fatalf("port = %d", target.Port)
				}
			}},
		{name: "the private key file", inventory: effectiveInventory,
			env: map[string]string{"ANSIBLE_PRIVATE_KEY_FILE": "/keys/ipa"},
			check: func(t *testing.T, target sshdial.Target) {
				if target.IdentityFile != "/keys/ipa" {
					t.Fatalf("identity file = %q", target.IdentityFile)
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv := writeEffectiveInventory(t, tc.inventory)
			if tc.cfg != "" {
				hermeticAnsibleConfig(t, tc.cfg)
			}
			for name, value := range tc.env {
				t.Setenv(name, value)
			}
			_, target, err := lockTargetFor(t, inv, nil)
			if tc.wantIn != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantIn) {
					t.Fatalf("err = %v, want it to hold %q", err, tc.wantIn)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, target)
		})
	}

	// Ansible gives a host or extra variable priority over ansible.cfg, so a
	// setting the lock cannot honor in the configuration does not matter when a
	// variable replaces it: the lock follows Ansible, in both directions.
	t.Run("an extra var replaces the refused ssh_args of ansible.cfg", func(t *testing.T) {
		inv := writeEffectiveInventory(t, effectiveInventory)
		hermeticAnsibleConfig(t, "[ssh_connection]\nssh_args = -o ProxyCommand=\"nc %h %p\"\n")
		if _, _, err := lockTargetFor(t, inv, nil); err == nil {
			t.Fatal("the ProxyCommand in ansible.cfg was not refused")
		}
		if _, _, err := lockTargetFor(t, inv, nil, "-e", "ansible_ssh_args='"+multiplex+"'"); err != nil {
			t.Fatalf("with ansible_ssh_args replacing it: %v", err)
		}
	})
}

// A lock that cannot know what the playbook will use refuses; it does not guess
// and it does not fall back to the inventory alone.
func TestIdentityLockTargetFailsClosedWhenItCannotRead(t *testing.T) {
	t.Run("an extra vars file that is not there", func(t *testing.T) {
		inv := writeEffectiveInventory(t, effectiveInventory)
		_, _, err := lockTargetFor(t, inv, nil, "-e", "@"+filepath.Join(t.TempDir(), "missing.yml"))
		if err == nil || !strings.Contains(err.Error(), "playbook 實際會用的 inventory 變數") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("a vault file Ansible has no password for", func(t *testing.T) {
		if _, err := exec.LookPath("ansible-vault"); err != nil {
			t.Skip("ansible-vault is not installed")
		}
		inv := writeEffectiveInventory(t, effectiveInventory)
		dir := t.TempDir()
		pw := filepath.Join(dir, "pw")
		vault := filepath.Join(dir, "main.yaml")
		if err := os.WriteFile(pw, []byte("not-a-real-password\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vault, []byte("ansible_host: 192.0.2.99\nipa_admin_password: sentinel-not-a-credential\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("ansible-vault", "encrypt", "--vault-password-file", pw, vault).CombinedOutput(); err != nil {
			t.Fatalf("ansible-vault encrypt: %v\n%s", err, out)
		}
		_, _, err := lockTargetFor(t, inv, nil, "-e", "@"+vault)
		if err == nil {
			t.Fatal("an encrypted extra vars file nobody could read was taken to say nothing about the connection")
		}
		if strings.Contains(err.Error(), "sentinel-not-a-credential") {
			t.Fatalf("the refusal shows a secret: %v", err)
		}
		// With the password the same file is read, and the override inside the
		// encrypted file is what the lock follows: the case `-e @.vault/main.yaml`
		// is in practice.
		_, target, err := lockTargetFor(t, inv, nil, "-e", "@"+vault, "--vault-password-file", pw)
		if err != nil {
			t.Fatal(err)
		}
		if target.Host != "192.0.2.99" {
			t.Fatalf("host = %s, want the one inside the encrypted file", target.Host)
		}
	})

	for name, tc := range map[string]struct {
		script string
		wantIn string
	}{
		"ansible-config fails":                {"#!/bin/sh\necho boom >&2\nexit 1\n", "ansible-config dump"},
		"ansible-config prints nonsense":      {"#!/bin/sh\necho 'not json'\n", "parse ansible-config output"},
		"ansible-config prints another shape": {"#!/bin/sh\necho '[{\"name\": \"EDITOR\", \"origin\": \"\", \"value\": \"vi\"}]'\n", "not the document this reads"},
	} {
		t.Run(name, func(t *testing.T) {
			inv := writeEffectiveInventory(t, effectiveInventory)
			bin := t.TempDir()
			if err := os.WriteFile(filepath.Join(bin, "ansible-config"), []byte(tc.script), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			_, _, err := lockTargetFor(t, inv, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantIn) {
				t.Fatalf("err = %v, want it to hold %q", err, tc.wantIn)
			}
		})
	}

	t.Run("no freeipa-server host at all", func(t *testing.T) {
		inv := writeEffectiveInventory(t, "all:\n  hosts:\n    web-1:\n      ansible_host: 192.0.2.20\n")
		_, _, err := lockTargetFor(t, inv, nil)
		if err == nil || !strings.Contains(err.Error(), "剛好一台 freeipa-server") {
			t.Fatalf("err = %v", err)
		}
	})
}

// The refusal says where a setting came from when it was not the inventory, so
// the operator looks in ansible.cfg or the environment and not at a host that
// sets nothing.
func TestIdentityLockTargetNamesTheSourceOfAConfiguredSetting(t *testing.T) {
	inv := writeEffectiveInventory(t, effectiveInventory)
	cfg := hermeticAnsibleConfig(t, "[ssh_connection]\nssh_args = -o ProxyCommand=\"nc %h %p\"\n")
	_, _, err := lockTargetFor(t, inv, nil)
	if err == nil {
		t.Fatal("not refused")
	}
	for _, want := range []string{"ansible_ssh_args <- ansible.cfg (" + cfg + ")", "ipa-1 沒有自己設定的連線變數"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("err = %v, want it to hold %q", err, want)
		}
	}
}

// The parser reads real ansible-config output (ansible-core 2.19.2, paths
// replaced), not output written to fit it (AGENTS.md §5.6).
func TestParseAnsibleConnectionConfigRealOutput(t *testing.T) {
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join("testdata", "ansible-config", name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	t.Run("overrides from ansible.cfg and the environment", func(t *testing.T) {
		got, err := parseAnsibleConnectionConfig(read("connection-overrides.json"))
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]any{
			"ansible_connection":      "local",
			"ansible_port":            float64(2200),
			"ansible_user":            "ops",
			"ansible_ssh_args":        `-o ProxyCommand="ssh -W %h:%p jump" -o ControlMaster=auto`,
			"ansible_ssh_common_args": "-o ProxyJump=bastion",
			"ansible_ssh_executable":  "/tmp/wrap",
		}
		if !reflect.DeepEqual(got.Vars, want) {
			t.Fatalf("vars = %#v\nwant   %#v", got.Vars, want)
		}
		if got.Origins["ansible_connection"] != "env: ANSIBLE_TRANSPORT" || got.Origins["ansible_ssh_executable"] != "env: ANSIBLE_SSH_EXECUTABLE" ||
			got.Origins["ansible_user"] != "ansible.cfg (/work/ansible.cfg)" {
			t.Fatalf("origins = %v", got.Origins)
		}
		if got.AskPass != "" {
			t.Fatalf("ask_pass = %q", got.AskPass)
		}
	})
	t.Run("the repo's own ansible.cfg and the runtime's ANSIBLE_SSH_ARGS", func(t *testing.T) {
		got, err := parseAnsibleConnectionConfig(read("repo-defaults.json"))
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"ansible_ssh_args": `-o ControlMaster=auto -o ControlPath="/home/u/.pilot/ssh/cp-%C" -o ControlPersist=60s`}
		if !reflect.DeepEqual(got.Vars, want) || got.Origins["ansible_ssh_args"] != "env: ANSIBLE_SSH_ARGS" {
			t.Fatalf("vars = %#v origins = %v", got.Vars, got.Origins)
		}
		// The target the lock builds from it has no extra option: multiplexing
		// is pilot's ssh's own business.
		if _, err := sshdial.TargetFromHostVars("ipa-1", got.Vars); err != nil {
			t.Fatalf("the repo's own configuration is refused: %v", err)
		}
	})
	t.Run("ask_pass", func(t *testing.T) {
		got, err := parseAnsibleConnectionConfig(read("ask-pass.json"))
		if err != nil {
			t.Fatal(err)
		}
		if got.AskPass != "env: ANSIBLE_ASK_PASS" || len(got.Vars) != 0 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("a document of another shape is an error, not no settings", func(t *testing.T) {
		for name, doc := range map[string]string{
			"not a list":         `{"name": "x"}`,
			"no connection part": `[{"name": "CONFIG_FILE", "origin": "", "value": null}]`,
			"no CONFIG_FILE":     `[{"CONNECTION_PLUGINS": []}]`,
			"plugins not a list": `[{"name": "CONFIG_FILE", "origin": "", "value": null}, {"CONNECTION_PLUGINS": {"ssh": []}}]`,
		} {
			if _, err := parseAnsibleConnectionConfig([]byte(doc)); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
	})
}

func TestWithConnectionDefaultsPrecedence(t *testing.T) {
	defaults := connectionDefaults{
		Vars:    map[string]any{"ansible_user": "cfg", "ansible_port": float64(2200), "ansible_ssh_args": "-o ControlMaster=auto"},
		Origins: map[string]string{"ansible_user": "ansible.cfg (/x)", "ansible_port": "ansible.cfg (/x)", "ansible_ssh_args": "env: ANSIBLE_SSH_ARGS"},
	}
	hostVars := map[string]any{"ansible_user": "host", "ansible_port": "", "ansible_host": "192.0.2.1"}
	merged, applied := withConnectionDefaults(hostVars, defaults)
	if merged["ansible_user"] != "host" {
		t.Errorf("the host's ansible_user lost to ansible.cfg: %v", merged["ansible_user"])
	}
	if merged["ansible_port"] != float64(2200) || merged["ansible_ssh_args"] != "-o ControlMaster=auto" || merged["ansible_host"] != "192.0.2.1" {
		t.Errorf("merged = %v", merged)
	}
	if want := []string{"ansible_port <- ansible.cfg (/x)", "ansible_ssh_args <- env: ANSIBLE_SSH_ARGS"}; !reflect.DeepEqual(applied, want) {
		t.Errorf("applied = %v, want %v", applied, want)
	}
	if hostVars["ansible_port"] != "" {
		t.Error("the host's own map was modified")
	}
}
