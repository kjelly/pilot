package sshdial

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/gateledger"
)

// TargetFromHostVars is the one rule for "which inventories can pilot's own
// ssh reach": the Go engine's tunnel and the identity lock both derive their
// Target from it. Each refusal below carries the message of its own gate: a
// refusal that came from another check would prove nothing about this one.

func TestTargetFromHostVars(t *testing.T) {
	// The shape pilot vm-target show-inventory prints.
	vmTarget := map[string]any{
		"ansible_connection":           "ssh",
		"ansible_host":                 "192.168.122.3",
		"ansible_user":                 "root",
		"ansible_port":                 22,
		"ansible_ssh_private_key_file": "/var/lib/libvirt/images/pilot/x/id_ed25519",
		"ansible_ssh_args":             `-o ControlMaster=auto -o ControlPath="/tmp/pilot-vmt-1000-171a9ac4/%C" -o ControlPersist=60s`,
		"ansible_ssh_common_args":      "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
		"ansible_ssh_pipelining":       true,
	}
	got, err := TargetFromHostVars("ipa-1", vmTarget)
	if err != nil {
		t.Fatal(err)
	}
	want := Target{Host: "192.168.122.3", User: "root", Port: 22, IdentityFile: "/var/lib/libvirt/images/pilot/x/id_ed25519",
		Options: map[string]string{"StrictHostKeyChecking": "no", "UserKnownHostsFile": "/dev/null"}}
	if got.Host != want.Host || got.User != want.User || got.Port != want.Port || got.IdentityFile != want.IdentityFile || !mapsEqual(got.Options, want.Options) {
		t.Fatalf("target = %+v\nwant   %+v", got, want)
	}
	if got, err := TargetFromHostVars("ipa-1.example.test", map[string]any{}); err != nil || got.Host != "ipa-1.example.test" {
		t.Fatalf("no ansible_host: %+v, %v", got, err)
	}
	// Each refusal, with the message of its own gate: a refusal that came
	// from another check would prove nothing about this one.
	for _, tc := range []struct {
		name string
		vars map[string]any
		gate string // the gates the case makes fire, comma separated
		want string // in the error
	}{
		{name: "docker connection", vars: map[string]any{"ansible_connection": "docker"}, gate: "ssh-connection", want: "ansible_connection 是 docker"},
		{name: "password", vars: map[string]any{"ansible_ssh_pass": "x"}, gate: "ssh-unsupported-var", want: "設定了 ansible_ssh_pass"},
		{name: "legacy host alias", vars: map[string]any{"ansible_ssh_host": "10.0.0.1"}, gate: "ssh-unsupported-var", want: "設定了 ansible_ssh_host"},
		{name: "an option sshdial does not allow", vars: map[string]any{"ansible_ssh_common_args": "-o ProxyCommand=nc"}, gate: "ssh-validate", want: "ProxyCommand"},
		{name: "option value with a space", vars: map[string]any{"ansible_ssh_common_args": `-o "ProxyJump=a b"`}, gate: "ssh-validate", want: "ipa-1："},
		{name: "short jump flag", vars: map[string]any{"ansible_ssh_common_args": "-J bastion"}, gate: "ssh-extra-args,opts-not-dash-o", want: "只接受 -o Key=Value"},
		{name: "an option without a value", vars: map[string]any{"ansible_ssh_extra_args": "-o StrictHostKeyChecking"}, gate: "ssh-extra-args,opts-not-key-value", want: "不是 Key=Value"},
		{name: "unbalanced quote", vars: map[string]any{"ansible_ssh_common_args": `-o "UserKnownHostsFile=/x`}, gate: "ssh-extra-args,opts-split,split-quote", want: "引號沒有成對"},
		{name: "a backslash", vars: map[string]any{"ansible_ssh_extra_args": `-o UserKnownHostsFile=C:\x`}, gate: "ssh-extra-args,opts-split,split-backslash", want: "不支援反斜線跳脫"},
		{name: "extra args that are not a string", vars: map[string]any{"ansible_ssh_common_args": 5}, gate: "ssh-extra-args,opts-not-string", want: "不是字串"},
		{name: "ssh_args that do not split", vars: map[string]any{"ansible_ssh_args": `-o "ControlPath=/x`}, gate: "ssh-args-parse,opts-split,split-quote", want: "ansible_ssh_args："},
		{name: "ssh_args beyond mux", vars: map[string]any{"ansible_ssh_args": "-o ControlMaster=auto -o ForwardAgent=yes"}, gate: "ssh-args-mux", want: "ansible_ssh_args 含 ForwardAgent"},
		{name: "non-integer port", vars: map[string]any{"ansible_port": "ssh"}, gate: "ssh-port", want: "ansible_port ssh 不是整數"},
		// A value of another type is refused, not ignored: ignoring
		// ansible_user 1000 connects as the local user (spec §4).
		{name: "a numeric ansible_user", vars: map[string]any{"ansible_user": 1000}, gate: "ssh-var-type", want: "ansible_user 是 int，不是字串"},
		{name: "a list ansible_user", vars: map[string]any{"ansible_user": []any{"root"}}, gate: "ssh-var-type", want: "ansible_user 是 []interface {}，不是字串"},
		{name: "a boolean ansible_host", vars: map[string]any{"ansible_host": true}, gate: "ssh-var-type", want: "ansible_host 是 bool，不是字串"},
		{name: "a numeric key file", vars: map[string]any{"ansible_ssh_private_key_file": 7}, gate: "ssh-var-type", want: "ansible_ssh_private_key_file 是 int，不是字串"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("gate: %s", tc.gate)
			_, err := TargetFromHostVars("ipa-1", tc.vars)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	// The options sshdial.Target allows pass through, a jump host among them: a
	// bastion in front of the FreeIPA server is a supported inventory.
	got, err = TargetFromHostVars("ipa-1", map[string]any{"ansible_ssh_common_args": "-o ProxyJump=bastion.example.test -o ConnectTimeout=7 -o ServerAliveInterval=5"})
	if err != nil || got.Options["ProxyJump"] != "bastion.example.test" || got.Options["ConnectTimeout"] != "7" || got.Options["ServerAliveInterval"] != "5" {
		t.Fatalf("allowlisted options: %+v, %v", got, err)
	}
	// What is not a refusal: an unset or null value keeps the default.
	for name, vars := range map[string]map[string]any{
		"null ansible_user":      {"ansible_user": nil},
		"null ansible_host":      {"ansible_host": nil},
		"empty ansible_host":     {"ansible_host": ""},
		"null key file":          {"ansible_ssh_private_key_file": nil},
		"numeric string port":    {"ansible_port": "2222"},
		"float port from a JSON": {"ansible_port": float64(2222)},
	} {
		if got, err := TargetFromHostVars("ipa-1", vars); err != nil || got.Host != "ipa-1" {
			t.Errorf("%s: %+v, %v", name, got, err)
		}
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// The gates of hostvars.go (AGENTS.md §5.10, §5.12): every refusal of the
// functions that hold them is named with a `// gate: <id>` comment, ids are
// unique, and each id has a row above that makes it fire or an exemption with
// its reason, so deleting a gate, or adding one nobody tested, fails here.
// The rows are the gate fields of this file's tables. They used to be tested
// in cmd/pilot/cmd (the Go preview's ledger) and moved with the function.
func TestTargetFromHostVarsEveryGateHasARow(t *testing.T) {
	res, err := gateledger.Scan("hostvars.go", nil, "TargetFromHostVars", "sshOptionArgs", "splitShellWords")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Returns) != 14 {
		t.Fatalf("found %d gates, want the 14 the function had when it moved: a holder lost a return", len(res.Returns))
	}
	rows, err := gateledger.RowGates("hostvars_test.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range gateledger.Check(res, rows, nil) {
		t.Error(p)
	}
}

// The ledger above would be vacuous if it could not fail; this proves it can
// on the real source: a copy of hostvars.go with a gate comment removed, or
// with an un-annotated refusal added, is reported.
func TestTargetFromHostVarsGateLedgerFiresOnTheRealSource(t *testing.T) {
	src, err := os.ReadFile("hostvars.go")
	if err != nil {
		t.Fatal(err)
	}
	scan := func(source string) []string {
		res, err := gateledger.Scan("hostvars.go", []byte(source), "TargetFromHostVars", "sshOptionArgs", "splitShellWords")
		if err != nil {
			t.Fatal(err)
		}
		rows := map[string]int{}
		for _, r := range res.Returns {
			rows[r.Gate] = 1
		}
		delete(rows, "")
		return gateledger.Check(res, rows, nil)
	}
	if p := scan(string(src)); len(p) != 0 {
		t.Fatalf("the unmodified source is not clean under its own rows: %v", p)
	}
	t.Run("a removed gate comment", func(t *testing.T) {
		mutated := strings.Replace(string(src), " // gate: ssh-connection\n", "\n", 1)
		if mutated == string(src) {
			t.Fatal("the ssh-connection gate comment is gone from the source")
		}
		if p := scan(mutated); !slices.ContainsFunc(p, func(s string) bool { return strings.Contains(s, "without a `// gate: <id>` comment") }) {
			t.Fatalf("problems = %v, want the un-annotated return", p)
		}
	})
	t.Run("an added refusal nobody named", func(t *testing.T) {
		const anchor = "\tt.Host = host\n"
		if !strings.Contains(string(src), anchor) {
			t.Fatal("the anchor line moved")
		}
		mutated := strings.Replace(string(src), anchor, "\tif host == \"\" {\n\t\treturn t, fmt.Errorf(\"new refusal\")\n\t}\n"+anchor, 1)
		if p := scan(mutated); !slices.ContainsFunc(p, func(s string) bool { return strings.Contains(s, "new refusal") }) {
			t.Fatalf("problems = %v, want the added return named", p)
		}
	})
}
