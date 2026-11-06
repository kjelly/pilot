package cmd

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// These tests drive the Go preview through the real cobra tree, the way an
// operator reaches it, and prove each fail-closed gate of spec §2.1–§2.2 on
// its own row: the gate's message or sentinel, exit code 1 (3 only for a
// produced plan with blocked objects, §2.3), and no more sent than the
// gate's step allows (nothing read before a §2.1 refusal, no tunnel before
// step 7, no JSON-RPC after a rejected login, session_logout after any
// failure after the login, no further read after a failed one), no plan
// file, and no secret anywhere (§2.4, §10.1). Each row names the gates it
// makes fire in its gate field; TestReconcileGolangEveryGateHasARow ties
// those names to the `// gate:` comments in the code, so a gate that no row
// reaches, or a new gate nobody named, fails (AGENTS.md §5.12).

// resetReconcileFlags puts every flag of the reconcile command (not the
// root's persistent ones, which hold the data directory under test) back to
// its default and clears Changed. A string-array flag keeps its own "changed"
// bit across Execute calls (pflag v1.0.9: the next Set appends), so it is
// emptied with Replace; Set(DefValue) would store the literal "[]". The
// subcommand's context is cleared too: cobra copies the root's context to a
// subcommand only while the subcommand's is nil.
func resetReconcileFlags() {
	reconcileCmd.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) {
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			_ = sv.Replace(nil)
		} else {
			_ = f.Value.Set(f.DefValue)
		}
		f.Changed = false
	})
	var none context.Context
	reconcileCmd.SetContext(none)
}

// runReconcileCLI runs `pilot reconcile <args>` through the real command
// tree, in the workspace and data directory the test set up.
func runReconcileCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	before := dataDir
	resetReconcileFlags()
	t.Cleanup(func() {
		resetReconcileFlags()
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})
	if dataDir != before {
		t.Fatalf("resetting the reconcile flags changed the data directory %q to %q", before, dataDir)
	}
	var out bytes.Buffer
	rootCmd.SetArgs(append([]string{"reconcile"}, args...))
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	err := rootCmd.ExecuteContext(context.Background())
	return out.String(), err
}

// toolCalls wraps ansible-inventory, ansible and ansible-vault (whatever is
// first on PATH now) so each call is logged, and returns a reader of the
// log. Install it after the fakes it should sit in front of.
func toolCalls(t *testing.T) func() []string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(bin, "calls")
	prev := os.Getenv("PATH")
	for _, name := range []string{"ansible-inventory", "ansible", "ansible-vault"} {
		body := "#!/bin/sh\necho " + name + " >> '" + log + "'\nPATH='" + prev + "' exec " + name + " \"$@\"\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+prev)
	return func() []string {
		data, _ := os.ReadFile(log)
		return strings.Fields(string(data))
	}
}

// processExitCode is the status cmd/pilot/main.go ends the process with for
// err: the error's ExitCode when it has one, else 1. (Not exitCodeOf, which
// network_check_test.go defines for another command.)
func processExitCode(err error) int {
	if err == nil {
		return 0
	}
	var c ExitCoder
	if errors.As(err, &c) {
		return c.ExitCode()
	}
	return 1
}

// assertNoSecretAnywhere fails when the admin password, a session cookie or
// a vault value is in the error, the output, the plan file if there is one,
// or any file of the pilot data directory.
func assertNoSecretAnywhere(t *testing.T, err error, out, plan string) {
	t.Helper()
	if dataDir == "" {
		t.Fatal("the pilot data directory is not the test's: the scan would read nothing")
	}
	secrets := []string{golangTestPassword, "fake-session-cookie-value", "sample-value-for-"}
	texts := map[string]string{"output": out}
	if err != nil {
		texts["error"] = err.Error()
	}
	if data, rerr := os.ReadFile(plan); rerr == nil {
		texts["plan"] = string(data)
	}
	_ = filepath.WalkDir(dataDir, func(p string, d fs.DirEntry, werr error) error {
		if werr == nil && !d.IsDir() {
			if data, rerr := os.ReadFile(p); rerr == nil {
				texts[p] = string(data)
			}
		}
		return nil
	})
	for where, text := range texts {
		for _, s := range secrets {
			if strings.Contains(text, s) {
				t.Fatalf("%q leaked into %s", s, where)
			}
		}
	}
}

// fakeTool puts an executable name running body first on PATH.
func fakeTool(t *testing.T, name, body string) {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

var golangPreviewArgs = []string{"--engine", "golang", "--preview-only", "--component", "freeipa-identity"}

// previewArgs is golangPreviewArgs plus more.
func previewArgs(more ...string) []string { return append(slices.Clone(golangPreviewArgs), more...) }

// noPlan fails when path exists.
func noPlan(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a plan was written: %v", err)
	}
}

// requests returns what the fake FreeIPA was sent: the request paths and the
// JSON-RPC methods, in order.
func (f *fakeIPA) requests() (paths, methods []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.paths), slices.Clone(f.methods)
}

// The harness resets its own state: a second run in the same process sees
// only its own --component, and the data directory the test set is kept.
func TestReconcileCLIHarnessResetsBetweenRuns(t *testing.T) {
	f := newFakeIPA(t, "p1-self")
	withFakeDialer(t, f)
	golangWorkspace(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1), nil)
	data := dataDir
	if out, err := runReconcileCLI(t, golangPreviewArgs...); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	_, err := runReconcileCLI(t, "--engine", "golang", "--preview-only", "--component", "dns")
	if err == nil || !strings.Contains(err.Error(), "只處理 --component freeipa-identity") {
		t.Fatalf("err = %v, want the component refusal", err)
	}
	if !slices.Equal(reconcileComponentFlags, []string{"dns"}) {
		t.Fatalf("components = %v: the first run's --component leaked into the second", reconcileComponentFlags)
	}
	if dataDir != data {
		t.Fatalf("data directory %q became %q", data, dataDir)
	}
	if out, err := runReconcileCLI(t); err == nil {
		t.Fatalf("a run with no flags went through (the engine flag leaked?)\n%s", out)
	}
	if reconcileEngineFlag != reconcileEngineAnsible || reconcilePreviewOnlyFlag || len(reconcileComponentFlags) != 0 {
		t.Fatalf("flags after a bare run: engine=%q preview=%v components=%v", reconcileEngineFlag, reconcilePreviewOnlyFlag, reconcileComponentFlags)
	}
}

// Spec §2.1: every refused combination, and the checks the command shares
// with the Ansible engine, stop the run before ansible-inventory, ansible or
// ansible-vault runs, before any tunnel, and write no plan.
func TestReconcileGolangFlagMatrix(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		gate string
		want string
	}{
		{name: "golang without --preview-only", args: []string{"--engine", "golang", "--component", "freeipa-identity"}, gate: "engine-preview-only,entry-engine-flags", want: "目前只提供預覽"},
		{name: "golang with --preview-only and --force", args: previewArgs("--force"), gate: "engine-preview-only", want: "目前只提供預覽"},
		{name: "golang with --force only", args: []string{"--engine", "golang", "--force", "--component", "freeipa-identity"}, gate: "engine-preview-only", want: "目前只提供預覽"},
		{name: "golang without --component", args: []string{"--engine", "golang", "--preview-only"}, gate: "engine-component", want: "只處理 --component freeipa-identity"},
		{name: "golang with another component", args: []string{"--engine", "golang", "--preview-only", "--component", "dns"}, gate: "engine-component", want: "只處理 --component freeipa-identity"},
		{name: "golang with two components", args: previewArgs("--component", "dns"), gate: "engine-component", want: "只處理 --component freeipa-identity"},
		{name: "golang with --actions", args: []string{"--engine", "golang", "--actions", "s.json"}, gate: "engine-actions", want: "--engine golang 不能與 --actions"},
		{name: "--plan-out without golang", args: []string{"--preview-only", "--component", "freeipa-identity", "--plan-out", "p.json"}, gate: "engine-plan-out", want: "--plan-out 只能與 --engine golang"},
		{name: "unknown engine", args: []string{"--engine", "go", "--preview-only", "--component", "freeipa-identity"}, gate: "engine-unknown", want: "--engine 只能是"},
		{name: "golang with an unknown stage", args: previewArgs("--stage", "foo"), gate: "entry-stage-flags", want: "--stage 只能是"},
		{name: "golang with an attestation but no prod", args: previewArgs("--stage", "sandbox", "--staging-attested-within-hours", "24"), gate: "entry-stage-flags", want: "只能搭配 --stage prod"},
		{name: "golang with a blank in --limit", args: previewArgs("--limit", "ipa-1 ipa-2"), gate: "entry-limit-flag", want: "--limit 不能含空白"},
		{name: "golang with a bad --timeout", args: previewArgs("--timeout", "soon"), gate: "timeout-parse", want: "--timeout 不是合法的 duration"},
		{name: "golang with a non-positive --timeout", args: previewArgs("--timeout", "0s"), gate: "timeout-parse", want: "--timeout 必須是正數"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("gate: %s", tc.gate)
			f := newFakeIPA(t, "p1-self")
			targets := withFakeDialer(t, f)
			dir := golangWorkspace(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1), nil)
			calls := toolCalls(t)
			plan := filepath.Join(dir, "p.json")
			out, err := runReconcileCLI(t, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) || processExitCode(err) != 1 {
				t.Fatalf("err = %v (exit %d), want %q and exit 1\n%s", err, processExitCode(err), tc.want, out)
			}
			if got := calls(); len(got) != 0 {
				t.Fatalf("read the workspace before refusing: %v", got)
			}
			if len(*targets) != 0 {
				t.Fatalf("built a tunnel: %+v", *targets)
			}
			assertNoLogin(t, f)
			noPlan(t, plan)
			assertNoSecretAnywhere(t, err, out, plan)
		})
	}
}

// Spec §2.1, §2.4: --plan-out names a file that must not exist, and its
// directory must: both refuse before anything is read, so the run does not
// read the whole directory and then fail to write the answer.
func TestReconcileGolangPlanOutIsCheckedFirst(t *testing.T) {
	for _, tc := range []struct {
		name string
		gate string
		want string
		// plan returns the --plan-out argument, given the workspace.
		plan func(t *testing.T, dir string) string
	}{
		{name: "the file exists", gate: "plan-out-exists", want: "已存在；不覆寫", plan: func(t *testing.T, dir string) string {
			path := filepath.Join(dir, "p.json")
			if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{name: "the file is a dangling symlink", gate: "plan-out-exists", want: "已存在；不覆寫", plan: func(t *testing.T, dir string) string {
			path := filepath.Join(dir, "p.json")
			if err := os.Symlink(filepath.Join(dir, "nowhere"), path); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{name: "its directory does not exist", gate: "plan-out-dir", want: "上層目錄", plan: func(t *testing.T, dir string) string {
			return filepath.Join(dir, "missing", "p.json")
		}},
		{name: "its directory is a file", gate: "plan-out-dir", want: "不存在或不是目錄", plan: func(t *testing.T, dir string) string {
			parent := filepath.Join(dir, "afile")
			if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(parent, "p.json")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("gate: %s", tc.gate)
			f := newFakeIPA(t, "p1-self")
			targets := withFakeDialer(t, f)
			dir := golangWorkspace(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1), nil)
			calls := toolCalls(t)
			plan := tc.plan(t, dir)
			out, err := runReconcileCLI(t, previewArgs("--plan-out", plan)...)
			if err == nil || !strings.Contains(err.Error(), tc.want) || processExitCode(err) != 1 {
				t.Fatalf("err = %v (exit %d), want %q and exit 1\n%s", err, processExitCode(err), tc.want, out)
			}
			if got := calls(); len(got) != 0 || len(*targets) != 0 {
				t.Fatalf("read %v and dialed %v before refusing the plan path", got, *targets)
			}
			assertNoLogin(t, f)
			if data, rerr := os.ReadFile(plan); rerr == nil && string(data) != "keep" {
				t.Fatalf("the existing plan file was changed to %q", data)
			}
			assertNoSecretAnywhere(t, err, out, plan)
		})
	}
}

// Spec §2.2 steps 2–4: the workspace failures a later gate would also stop,
// each with its own message, and no tunnel, login or plan.
func TestReconcileGolangWorkspaceFailures(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		setup func(t *testing.T, dir string)
		gate  string
		want  string
	}{
		{name: "the inventory file is missing", args: []string{"-i", "missing.yml"}, gate: "inventory-missing", want: "找不到檔案"},
		{name: "the pilot data directory cannot be created", gate: "runtime-prepare", want: "create Ansible data directory", setup: func(t *testing.T, dir string) {
			blocker := filepath.Join(dir, "blocker")
			writePrivateFile(t, blocker, "a file where the data directory would go")
			dataDir = filepath.Join(blocker, "data")
		}},
		{name: "ansible-inventory fails", gate: "ansible-inventory", want: "ansible-inventory --list", setup: func(t *testing.T, _ string) {
			fakeTool(t, "ansible-inventory", "echo '[ERROR]: synthetic inventory failure' >&2\nexit 1")
		}},
		{name: "a plaintext secret in group_vars is refused before ansible-inventory runs", gate: "ansible-inventory", want: "ipa_admin_password", setup: func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "group_vars"), 0o700); err != nil {
				t.Fatal(err)
			}
			writePrivateFile(t, filepath.Join(dir, "group_vars", "all.yml"), "ipa_admin_password: group-vars-secret-1\n")
		}},
		{name: "ansible --list-hosts fails", gate: "list-hosts", want: "ansible freeipa-server --list-hosts", setup: func(t *testing.T, _ string) {
			fakeTool(t, "ansible", "echo '[ERROR]: synthetic list-hosts failure' >&2\nexit 4")
		}},
		{name: "the roster is not YAML", gate: "roster-yaml", want: "解析 roster", setup: func(t *testing.T, dir string) {
			writePrivateFile(t, filepath.Join(dir, ".vault", "ipa-identity.yaml"), "schema_version: 3\nusers: [\n")
		}},
		{name: "no freeipa_roster_file: completeness refuses first", gate: "completeness", want: "no freeipa_roster_file", setup: func(t *testing.T, _ string) {
			golangServers(t, golangServer{name: "ipa-1", addr: "192.0.2.10", vars: map[string]any{"freeipa_roster_file": ""}})
		}},
		{name: "the roster's freeipa.server is a number", gate: "roster-server-type,roster-server-value", want: "freeipa.server 是 int，不是字串", setup: func(t *testing.T, dir string) {
			writePrivateFile(t, filepath.Join(dir, ".vault", "ipa-identity.yaml"), withRosterServer("123"))
		}},
		{name: "the roster's freeipa.server is a list", gate: "roster-server-type,roster-server-value", want: "freeipa.server 是 []interface {}，不是字串", setup: func(t *testing.T, dir string) {
			writePrivateFile(t, filepath.Join(dir, ".vault", "ipa-identity.yaml"), withRosterServer("[ipa.example.test]"))
		}},
		{name: "hosts.yml is not YAML", gate: "hosts-parse", want: "parse source file", setup: func(t *testing.T, dir string) {
			writePrivateFile(t, filepath.Join(dir, "hosts.yml"), "hosts: [\n")
		}},
		{name: "hosts.yml cannot be read", gate: "hosts-read", want: "is a directory", setup: func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, "hosts.yml"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hosts.yml does not render", gate: "hosts-render", want: "refusing to generate", setup: func(t *testing.T, dir string) {
			writePrivateFile(t, filepath.Join(dir, "hosts.yml"), "hosts:\n  ipa-1:\n    ansible_host: \"192.0.2.10\"\n    roles: [no-such-role]\n")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("gate: %s", tc.gate)
			f := newFakeIPA(t, "p1-self")
			targets := withFakeDialer(t, f)
			dir := golangWorkspace(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1), nil)
			if tc.setup != nil {
				tc.setup(t, dir)
			}
			plan := filepath.Join(dir, "p.json")
			out, err := runReconcileCLI(t, previewArgs(append([]string{"--plan-out", plan}, tc.args...)...)...)
			if err == nil || !strings.Contains(err.Error(), tc.want) || processExitCode(err) != 1 {
				t.Fatalf("err = %v (exit %d), want %q and exit 1\n%s", err, processExitCode(err), tc.want, out)
			}
			if len(*targets) != 0 {
				t.Fatalf("built a tunnel: %+v", *targets)
			}
			assertNoLogin(t, f)
			noPlan(t, plan)
			assertNoSecretAnywhere(t, err, out, plan)
			if strings.Contains(err.Error(), "group-vars-secret-1") {
				t.Fatalf("the refusal shows the secret it found: %v", err)
			}
		})
	}
}

// Issue #273, spec §2.2 step 4: a password, ssh_keys or membership that is not
// a mapping, null included (and the other wrong types the roster validator
// lets through), used to be read as "not declared", which for a group is an
// authoritative group with no members and, once the engine writes, the removal
// of every direct member. The playbook's gate fails on null as well. Each row
// is a roster that passes inventory.ValidateRoster, so the refusal is the
// adapter's (gate roster-adapter): exit 1 with the field and the roster object
// named, nothing dialed, nothing sent to FreeIPA, no plan, and no value in the
// error.
func TestReconcileGolangRefusesWrongTypedRosterValues(t *testing.T) {
	const sentinel = "pw-sentinel-not-a-real-secret"
	base := strings.Replace(captureRoster, "%s", "/bin/sh", 1)
	withUserField := func(user, field string) string {
		return strings.Replace(base, "{name: "+user+", ", "{name: "+user+", "+field+", ", 1)
	}
	withGroup := func(membership string) string {
		return base + "groups:\n  - {name: team-a, category: team, membership: " + membership + "}\n"
	}
	for _, tc := range []struct {
		name, roster, gate, want string
	}{
		{name: "password is a string", roster: withUserField("p1-nopw", `password: "`+sentinel+`"`), gate: "roster-adapter",
			want: "users[2] (p1-nopw): password must be a mapping, not string"},
		{name: "password.initial is a number", roster: withUserField("p1-nopw", "password: {initial: 7}"), gate: "roster-adapter",
			want: "users[2] (p1-nopw): password: initial must be a string, not int"},
		{name: "ssh_keys is a list", roster: withUserField("p1-keys", `ssh_keys: ["`+sentinel+`"]`), gate: "roster-adapter",
			want: "users[0] (p1-keys): ssh_keys must be a mapping, not []interface {}"},
		{name: "ssh_keys.authoritative is a string", roster: withUserField("p1-keys", `ssh_keys: {authoritative: "no"}`), gate: "roster-adapter",
			want: "users[0] (p1-keys): ssh_keys: authoritative must be true or false"},
		{name: "membership is a list of members", roster: withGroup("[p1-self]"), gate: "roster-adapter",
			want: "groups[0] (team-a): membership must be a mapping, not []interface {}"},
		{name: "membership is a string", roster: withGroup(`"p1-self"`), gate: "roster-adapter",
			want: "groups[0] (team-a): membership must be a mapping, not string"},
		{name: "membership is an empty stanza (null)", roster: base + "groups:\n  - name: team-a\n    category: team\n    membership:\n", gate: "roster-adapter",
			want: "groups[0] (team-a): membership must be a mapping, not null"},
		{name: "membership is ~ (null)", roster: withGroup("~"), gate: "roster-adapter",
			want: "groups[0] (team-a): membership must be a mapping, not null"},
		{name: "password is null", roster: withUserField("p1-nopw", "password: ~"), gate: "roster-adapter",
			want: "users[2] (p1-nopw): password must be a mapping, not null"},
		{name: "ssh_keys is null", roster: withUserField("p1-keys", "ssh_keys: ~"), gate: "roster-adapter",
			want: "users[0] (p1-keys): ssh_keys must be a mapping, not null"},
		{name: "users is a string", roster: "schema_version: 3\nusers: " + sentinel + "\n", gate: "roster-adapter",
			want: "users must be a list, not string"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("gate: %s", tc.gate)
			f := newFakeIPA(t, "p1-self")
			targets := withFakeDialer(t, f)
			dir := golangWorkspace(t, tc.roster, nil)
			plan := filepath.Join(dir, "p.json")
			out, err := runReconcileCLI(t, previewArgs("--plan-out", plan)...)
			if err == nil || !strings.Contains(err.Error(), tc.want) || processExitCode(err) != 1 {
				t.Fatalf("err = %v (exit %d), want %q and exit 1\n%s", err, processExitCode(err), tc.want, out)
			}
			if len(*targets) != 0 {
				t.Fatalf("built a tunnel: %+v", *targets)
			}
			if paths, methods := f.requests(); len(paths)+len(methods) != 0 {
				t.Fatalf("sent %v %v to FreeIPA", paths, methods)
			}
			assertNoLogin(t, f)
			noPlan(t, plan)
			if strings.Contains(out, "唯讀預覽（不寫入 FreeIPA）") || strings.Contains(out, "plan JSON：") {
				t.Fatalf("a refused roster printed a preview:\n%s", out)
			}
			assertNoSecretAnywhere(t, err, out, plan)
			if strings.Contains(err.Error(), sentinel) || strings.Contains(out, sentinel) {
				t.Fatalf("the refusal shows the value it refused: %v", err)
			}
		})
	}
}

// withRosterServer is the capture roster declaring freeipa.server as the given
// YAML value.
func withRosterServer(value string) string {
	return strings.Replace(strings.Replace(captureRoster, "%s", "/bin/sh", 1),
		"  admin: {principal: p1-self}\n", "  server: "+value+"\n  admin: {principal: p1-self}\n", 1)
}

func writePrivateFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// pingWithAPI is the captured `ping` answer with another API version.
func pingWithAPI(t *testing.T, f *fakeIPA, version string) string {
	t.Helper()
	data := string(f.fixture("ping"))
	if !strings.Contains(data, "API version 2.257") {
		t.Fatal("the ping capture no longer holds API version 2.257")
	}
	return strings.Replace(data, "API version 2.257", "API version "+version, 1)
}

// Spec §2.2 steps 7–8: the failures between the tunnel and the plan. Each
// ends in the gate's own error, sends only what its step allows (the exact
// requests are listed), ends the session when there was one, writes no plan
// and prints no preview banner.
func TestReconcileGolangSessionAndObserveFailures(t *testing.T) {
	const login = "/ipa/session/login_password"
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T, f *fakeIPA)
		fault   func()
		gate    string
		want    []string // in the error
		check   func(t *testing.T, err error)
		paths   []string // the request paths in order, when nothing is answered as JSON-RPC (nil: none)
		methods []string // the JSON-RPC methods answered, in order, ending with the logout when there was a session
	}{
		{name: "the FQDN cannot be read", gate: "fqdn-read",
			fault: func() { golangDialerFaults.fqdnErr = errors.New("synthetic hostname -f failure") },
			want:  []string{"讀取 ipa-1 的 FQDN", "synthetic hostname -f failure"}},
		{name: "the IPA CA cannot be read", gate: "ca-read",
			fault: func() { golangDialerFaults.caErr = errors.New("synthetic ca.crt failure") },
			want:  []string{"讀取 ipa-1 的 IPA CA", "synthetic ca.crt failure"}},
		{name: "the client refuses the FQDN", gate: "client-new",
			fault: func() { golangDialerFaults.fqdn = "ipa_1.example.test" },
			want:  []string{"invalid server FQDN"}},
		{name: "login rejected: invalid password (captured)", gate: "login",
			setup: func(_ *testing.T, f *fakeIPA) { f.login = "login-invalid-password" },
			want:  []string{"登入 FreeIPA", "invalid-password"},
			check: func(t *testing.T, err error) {
				var le *freeiparpc.LoginError
				if !errors.As(err, &le) || le.Status != 401 {
					t.Fatalf("err = %v, want a *LoginError with status 401", err)
				}
			},
			paths: []string{login}},
		{name: "login rejected: password expired (captured)", gate: "login",
			setup: func(_ *testing.T, f *fakeIPA) { f.login = "login-password-expired" },
			want:  []string{"登入 FreeIPA", "password-expired"},
			paths: []string{login}},
		{name: "API version not supported", gate: "check-server",
			setup:   func(t *testing.T, f *fakeIPA) { f.answers = map[string]string{"ping": pingWithAPI(t, f, "2.260")} },
			want:    []string{"API version 2.260", "supported"},
			methods: []string{"ping", "session_logout"}},
		{name: "the login is not in admins (D7)", gate: "observe",
			setup:   func(_ *testing.T, f *fakeIPA) { f.noAdmins = true },
			want:    []string{"not a member of admins"},
			methods: []string{"ping", "user_find", "session_logout"}},
		{name: "the roster's admin is not among the users", gate: "observe",
			setup: func(t *testing.T, _ *fakeIPA) {
				writePrivateFile(t, filepath.Join(".vault", "ipa-identity.yaml"), strings.Replace(strings.Replace(captureRoster, "%s", "/bin/sh", 1), "principal: p1-self", "principal: p1-ghost", 1))
			},
			want:    []string{"p1-ghost", "not among the users"},
			methods: []string{"ping", "user_find", "session_logout"}},
		{name: "user_find truncated (captured)", gate: "observe",
			setup: func(_ *testing.T, f *fakeIPA) { f.answers = map[string]string{"user_find": "user-find-truncated"} },
			check: func(t *testing.T, err error) {
				if !errors.Is(err, freeiparpc.ErrTruncated) {
					t.Fatalf("err = %v, want ErrTruncated", err)
				}
			},
			want:    []string{"read users"},
			methods: []string{"ping", "user_find", "session_logout"}},
		{name: "group_find over the server's size limit (captured)", gate: "observe",
			setup: func(_ *testing.T, f *fakeIPA) {
				f.answers = map[string]string{"group_find": "k3-dssize3-sizelimit0-groups"}
			},
			check: func(t *testing.T, err error) {
				if !freeiparpc.IsRPC(err, "SizeLimitExceeded") {
					t.Fatalf("err = %v, want SizeLimitExceeded", err)
				}
			},
			want:    []string{"read groups"},
			methods: []string{"ping", "user_find", "user_find", "group_find", "session_logout"}},
		{name: "group_find over the server's look-through limit (captured)", gate: "observe",
			setup: func(_ *testing.T, f *fakeIPA) {
				f.answers = map[string]string{"group_find": "k3-dslook3-sizelimit0-groups"}
			},
			want: []string{"read groups"}, methods: []string{"ping", "user_find", "user_find", "group_find", "session_logout"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("gate: %s", tc.gate)
			f := newFakeIPA(t, "p1-self")
			withFakeDialer(t, f)
			dir := golangWorkspace(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1), nil)
			if tc.setup != nil {
				tc.setup(t, f)
			}
			if tc.fault != nil {
				tc.fault()
			}
			plan := filepath.Join(dir, "p.json")
			out, err := runReconcileCLI(t, previewArgs("--plan-out", plan)...)
			if err == nil || processExitCode(err) != 1 {
				t.Fatalf("err = %v (exit %d), want a failure that exits 1\n%s", err, processExitCode(err), out)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("err = %v, want it to hold %q", err, w)
				}
			}
			if tc.check != nil {
				tc.check(t, err)
			}
			paths, methods := f.requests()
			if tc.methods != nil {
				if !slices.Equal(methods, tc.methods) {
					t.Fatalf("methods = %v, want %v", methods, tc.methods)
				}
			} else if !slices.Equal(paths, tc.paths) || len(methods) != 0 {
				t.Fatalf("requests = %v (methods %v), want exactly %v and no JSON-RPC", paths, methods, tc.paths)
			}
			noPlan(t, plan)
			if strings.Contains(out, "唯讀預覽（不寫入 FreeIPA）") {
				t.Fatalf("a failed preview printed a plan:\n%s", out)
			}
			assertNoSecretAnywhere(t, err, out, plan)
		})
	}
}

// Spec §2.4: the plan is written last and only for a plan the preview
// stands behind. A file that appears during the run is not replaced; a
// client that sent a write has no plan to show (D10, §6.1); a plan with
// blocked objects is written and exits 3, and every other failure exits 1.
func TestReconcileGolangPlanOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name string
		gate string
		run  func(t *testing.T)
	}{
		{name: "a plan file that appears mid-run is kept", gate: "plan-write,plan-open", run: func(t *testing.T) {
			f := newFakeIPA(t, "p1-self")
			withFakeDialer(t, f)
			dir := golangWorkspace(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1), nil)
			plan := filepath.Join(dir, "p.json")
			prev := newGolangIPAClient
			t.Cleanup(func() { newGolangIPAClient = prev })
			newGolangIPAClient = func(cfg freeiparpc.Config) (*freeiparpc.Client, error) {
				writePrivateFile(t, plan, "keep")
				return prev(cfg)
			}
			out, err := runReconcileCLI(t, previewArgs("--plan-out", plan)...)
			if err == nil || !strings.Contains(err.Error(), "--plan-out:") || processExitCode(err) != 1 {
				t.Fatalf("err = %v (exit %d)\n%s", err, processExitCode(err), out)
			}
			if data, _ := os.ReadFile(plan); string(data) != "keep" {
				t.Fatalf("the plan replaced a file that appeared mid-run: %q", data)
			}
			if strings.Contains(out, "plan JSON：") {
				t.Fatalf("announced a plan file it did not write:\n%s", out)
			}
			assertNoSecretAnywhere(t, err, out, plan)
		}},
		{name: "a client that sent a write has no plan to show", gate: "writes-guard", run: func(t *testing.T) {
			f := newFakeIPA(t, "p1-self")
			withFakeDialer(t, f)
			dir := golangWorkspace(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1), nil)
			prev := newGolangIPAClient
			t.Cleanup(func() { newGolangIPAClient = prev })
			newGolangIPAClient = func(cfg freeiparpc.Config) (*freeiparpc.Client, error) {
				cfg.ReadOnly = false
				c, err := prev(cfg)
				if err != nil {
					return nil, err
				}
				// Sent without a session: the fake answers 401 and changes
				// nothing, but the client has counted one write.
				_, _ = c.Call(context.Background(), freeiparpc.Command{Method: "user_mod", Args: []any{"p1-self"}})
				return c, nil
			}
			plan := filepath.Join(dir, "p.json")
			out, err := runReconcileCLI(t, previewArgs("--plan-out", plan)...)
			if err == nil || !strings.Contains(err.Error(), "內部錯誤：預覽送出了 1 個寫入") || processExitCode(err) != 1 {
				t.Fatalf("err = %v (exit %d)\n%s", err, processExitCode(err), out)
			}
			noPlan(t, plan)
			if strings.Contains(out, "唯讀預覽（不寫入 FreeIPA）") || strings.Contains(out, "plan JSON：") {
				t.Fatalf("a preview that sent a write printed or announced a plan:\n%s", out)
			}
			assertNoSecretAnywhere(t, err, out, plan)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("gate: %s", tc.gate)
			tc.run(t)
		})
	}
}

// Spec §2.3: exit 3 is a produced plan with blocked objects, written to
// --plan-out; every other failure exits 1, also when the failing step is a
// child process whose own status (ansible's 3 or 4) would otherwise become
// pilot's: an error wrapping an *exec.ExitError is an ExitCoder, and a 3
// with no plan would read as "blocked".
func TestReconcileGolangExitCodes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		roster   string // %s is the login shell of p1-self
		setup    func(t *testing.T)
		gate     string
		wantCode int
		wantPlan string // "blocked" when the plan must be written
		want     string // in the error
	}{
		{name: "blocked plan", roster: "/bin/sh, uid: 1", gate: "blocked-plan,entry-golang-dispatch,exit-code-passthrough", wantCode: 3, wantPlan: "blocked", want: "個物件被阻擋"},
		{name: "ansible --list-hosts exits 3", roster: "/bin/sh", gate: "exit-code-1", wantCode: 1, want: "list-hosts",
			setup: func(t *testing.T) { fakeTool(t, "ansible", "echo '[ERROR]: synthetic' >&2\nexit 3") }},
		{name: "ansible --list-hosts exits 4", roster: "/bin/sh", gate: "exit-code-1", wantCode: 1, want: "list-hosts",
			setup: func(t *testing.T) { fakeTool(t, "ansible", "echo '[ERROR]: synthetic' >&2\nexit 4") }},
		{name: "ansible-inventory exits 3", roster: "/bin/sh", gate: "exit-code-1", wantCode: 1, want: "ansible-inventory",
			setup: func(t *testing.T) { fakeTool(t, "ansible-inventory", "echo '[ERROR]: synthetic' >&2\nexit 3") }},
		{name: "ansible-vault exits 3", roster: "/bin/sh", gate: "exit-code-1", wantCode: 1, want: "讀取 vault vars 檔",
			setup: func(t *testing.T) {
				writeEncrypted(t, filepath.Join(".vault", "main.yaml"))
				golangFakeVault(t, "echo '[ERROR]: synthetic' >&2\nexit 3")
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("gate: %s", tc.gate)
			f := newFakeIPA(t, "p1-self")
			withFakeDialer(t, f)
			dir := golangWorkspace(t, strings.Replace(captureRoster, "%s", tc.roster, 1), nil)
			if tc.setup != nil {
				tc.setup(t)
			}
			plan := filepath.Join(dir, "p.json")
			out, err := runReconcileCLI(t, previewArgs("--plan-out", plan)...)
			if err == nil || processExitCode(err) != tc.wantCode || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, exit %d, want exit %d and %q\n%s", err, processExitCode(err), tc.wantCode, tc.want, out)
			}
			if tc.wantPlan == "" {
				noPlan(t, plan)
				assertNoSecretAnywhere(t, err, out, plan)
				return
			}
			info, serr := os.Stat(plan)
			if serr != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("plan file: %v %v", info, serr)
			}
			data, _ := os.ReadFile(plan)
			if !strings.Contains(string(data), `"result": "`+tc.wantPlan+`"`) || !strings.Contains(string(data), "uid_or_gid_change") {
				t.Fatalf("plan = %s", data)
			}
			if !strings.Contains(out, "plan JSON："+plan) {
				t.Fatalf("the plan file is not announced:\n%s", out)
			}
			assertNoSecretAnywhere(t, err, out, plan)
		})
	}
}

// Spec §2.1: --timeout is the Go preview's whole budget, and the help says
// so (the Ansible engine's is per ansible-playbook call).
func TestReconcileTimeoutHelpNamesBothMeanings(t *testing.T) {
	usage := reconcileCmd.Flags().Lookup("timeout").Usage
	for _, want := range []string{"ansible-playbook", "--engine golang", "ansible-inventory", "--list-hosts", "ansible-vault", "FreeIPA"} {
		if !strings.Contains(usage, want) {
			t.Errorf("--timeout help %q does not mention %q", usage, want)
		}
	}
}

// Spec §3: Ctrl-C ends the preview like --timeout does: the vault read is
// killed (with the ansible-vault it started) and nothing is dialed. In a
// child process: a preview that does not catch SIGINT dies of it there,
// failing this test instead of the package.
func TestReconcileGolangInterruptStopsTheVaultRead(t *testing.T) {
	runIsolated(t, 90*time.Second, func(t *testing.T) {
		f := newFakeIPA(t, "p1-self")
		targets := withFakeDialer(t, f)
		golangWorkspace(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1), nil)
		writeEncrypted(t, filepath.Join(".vault", "ipa-identity.yaml"))
		started := filepath.Join(t.TempDir(), "started")
		golangFakeVault(t, "echo $$ > '"+started+".tmp'\nmv '"+started+".tmp' '"+started+"'\nexec sleep 60")
		resetReconcileFlags()
		var out bytes.Buffer
		rootCmd.SetArgs(append([]string{"reconcile"}, previewArgs("--timeout", "10m")...))
		rootCmd.SetOut(&out)
		rootCmd.SetErr(&out)
		t.Cleanup(func() { resetReconcileFlags(); rootCmd.SetArgs(nil); rootCmd.SetOut(nil); rootCmd.SetErr(nil) })
		done := make(chan error, 1)
		go func() { done <- rootCmd.ExecuteContext(context.Background()) }()
		pid := waitForPID(t, started, 30*time.Second)
		begin := time.Now()
		if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
			t.Fatal(err)
		}
		var err error
		select {
		case err = <-done:
		case <-time.After(20 * time.Second):
			t.Fatal("Ctrl-C did not stop the preview")
		}
		if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "讀取 roster") || processExitCode(err) != 1 {
			t.Fatalf("err = %v (exit %d) after %s, want the canceled roster read and exit 1\n%s", err, processExitCode(err), time.Since(begin), out.String())
		}
		if kerr := syscall.Kill(pid, 0); !errors.Is(kerr, syscall.ESRCH) {
			t.Fatalf("ansible-vault (pid %d) outlived the interrupt: kill 0 = %v", pid, kerr)
		}
		if len(*targets) != 0 {
			t.Fatalf("built a tunnel: %+v", *targets)
		}
		assertNoLogin(t, f)
	})
}

// waitForPID reads the pid a fake tool wrote to path once the file appears.
func waitForPID(t *testing.T, path string, within time.Duration) int {
	t.Helper()
	for deadline := time.Now().Add(within); ; time.Sleep(20 * time.Millisecond) {
		if data, err := os.ReadFile(path); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
				return pid
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not appear within %s", path, within)
		}
	}
}
