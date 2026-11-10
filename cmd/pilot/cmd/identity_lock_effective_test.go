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

// A value set in the inventory for one host only cannot say what the play's
// hosts: resolves to: two different answers are an error, not a pick.
func TestEffectiveTargetGroup(t *testing.T) {
	for _, tc := range []struct {
		name    string
		vars    map[string]map[string]any
		want    string
		wantErr string
	}{
		{"unset", map[string]map[string]any{"a": {}, "b": {"x": 1}}, identityDefaultTargetGroup, ""},
		{"no hosts", map[string]map[string]any{}, identityDefaultTargetGroup, ""},
		{"nil is unset", map[string]map[string]any{"a": {"target_group": nil}}, identityDefaultTargetGroup, ""},
		{"one value on every host", map[string]map[string]any{"a": {"target_group": "g"}, "b": {"target_group": "g"}}, "g", ""},
		{"one host sets it", map[string]map[string]any{"a": {"target_group": " g "}, "b": {}}, "g", ""},
		{"hosts disagree", map[string]map[string]any{"a": {"target_group": "g"}, "b": {"target_group": "h"}}, "", "不一致(g、h)"},
		{"not a string", map[string]map[string]any{"a": {"target_group": 3.0}}, "", "非空的字串"},
		{"blank", map[string]map[string]any{"a": {"target_group": "  "}}, "", "非空的字串"},
		{"an option", map[string]map[string]any{"a": {"target_group": "-m"}}, "", "以 - 開頭"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := effectiveTargetGroup(tc.vars)
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
