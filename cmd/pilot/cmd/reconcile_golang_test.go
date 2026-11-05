package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/sshdial"
)

func TestValidateReconcileEngineFlags(t *testing.T) {
	identity := []string{"freeipa-identity"}
	for _, tc := range []struct {
		name                  string
		engine                string
		preview, force        bool
		components            []string
		actions, planOut, err string
	}{
		{name: "ansible default", engine: "ansible", preview: true, components: identity},
		{name: "golang preview", engine: "golang", preview: true, components: identity, planOut: "p.json"},
		{name: "unknown engine", engine: "go", preview: true, components: identity, err: "--engine 只能是"},
		{name: "golang without preview", engine: "golang", components: identity, err: "只提供預覽"},
		{name: "golang with force", engine: "golang", force: true, components: identity, err: "只提供預覽"},
		{name: "golang other component", engine: "golang", preview: true, components: []string{"dns"}, err: "只處理 --component freeipa-identity"},
		{name: "golang two components", engine: "golang", preview: true, components: []string{"freeipa-identity", "dns"}, err: "只處理"},
		{name: "golang no component", engine: "golang", preview: true, err: "只處理"},
		{name: "golang with actions", engine: "golang", preview: true, components: identity, actions: "s.json", err: "--actions"},
		{name: "plan-out without golang", engine: "ansible", preview: true, components: identity, planOut: "p.json", err: "--plan-out"},
	} {
		err := validateReconcileEngineFlags(tc.engine, tc.preview, tc.force, tc.components, tc.actions, tc.planOut)
		if tc.err == "" && err != nil || tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.err)
		}
	}
}

// The Go stage gate must accept exactly what the playbook's three
// cross-check asserts accept (AGENTS.md §4.3, §5.7).
func TestGolangPreviewStageMatchesThePlaybookGate(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "playbooks", "apply", "freeipa-identity-apply.yml"))
	if err != nil {
		t.Fatal(err)
	}
	gate := regexp.MustCompile(`(?s)name: "Gate: stage must match this host's inventory environment group"\s+ansible\.builtin\.assert:\s+that:\s+(- .*?\n\s+- .*?\n\s+- .*?\n)`).FindSubmatch(data)
	if gate == nil {
		t.Fatal("the playbook's stage cross-check assert was not found")
	}
	want := []string{
		"- not ('prod' in group_names and stage != 'prod')",
		"- not ('staging' in group_names and stage != 'staging')",
		"- not (stage in ['staging', 'prod'] and stage not in group_names)",
	}
	var got []string
	for _, line := range strings.Split(strings.TrimSpace(string(gate[1])), "\n") {
		got = append(got, strings.TrimSpace(line))
	}
	if !slices.Equal(got, want) {
		t.Fatalf("the playbook gate changed:\n%v\nupdate golangPreviewStage to match", got)
	}
	for _, env := range []string{"", "staging", "prod"} {
		for _, stage := range []string{"sandbox", "staging", "prod"} {
			groups := map[string][]string{}
			if env != "" {
				groups[env] = []string{"ipa-1"}
			}
			names := groups
			in := func(g string) bool { return slices.Contains(names[g], "ipa-1") }
			// The three that: items of the playbook's cross-check, each
			// `not (a and b)` written as `!a || !b`.
			allowed := (!in("prod") || stage == "prod") &&
				(!in("staging") || stage == "staging") &&
				(stage != "staging" && stage != "prod" || in(stage))
			_, err := golangPreviewStage("ipa-1", groups, stage, "24")
			if allowed != (err == nil) {
				t.Errorf("env %q stage %s: err = %v, playbook allows = %v", env, stage, err, allowed)
			}
		}
	}
	if _, err := golangPreviewStage("ipa-1", map[string][]string{"prod": {"ipa-1"}}, "prod", ""); err == nil {
		t.Error("prod without an attestation passed")
	}
	if stage, err := golangPreviewStage("ipa-1", nil, "", ""); stage != "sandbox" || err != nil {
		t.Errorf("default stage = %s, %v", stage, err)
	}
}

func TestSSHTargetFromHostVars(t *testing.T) {
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
	got, err := sshTargetFromHostVars("ipa-1", vmTarget)
	if err != nil {
		t.Fatal(err)
	}
	want := sshdial.Target{Host: "192.168.122.3", User: "root", Port: 22, IdentityFile: "/var/lib/libvirt/images/pilot/x/id_ed25519",
		Options: map[string]string{"StrictHostKeyChecking": "no", "UserKnownHostsFile": "/dev/null"}}
	if got.Host != want.Host || got.User != want.User || got.Port != want.Port || got.IdentityFile != want.IdentityFile || !mapsEqual(got.Options, want.Options) {
		t.Fatalf("target = %+v\nwant   %+v", got, want)
	}
	if got, err := sshTargetFromHostVars("ipa-1.example.test", map[string]any{}); err != nil || got.Host != "ipa-1.example.test" {
		t.Fatalf("no ansible_host: %+v, %v", got, err)
	}
	for name, vars := range map[string]map[string]any{
		"docker connection":    {"ansible_connection": "docker"},
		"password":             {"ansible_ssh_pass": "x"},
		"legacy host alias":    {"ansible_ssh_host": "10.0.0.1"},
		"unsupported option":   {"ansible_ssh_common_args": "-o ProxyCommand=nc"},
		"short jump flag":      {"ansible_ssh_common_args": "-J bastion"},
		"ssh_args beyond mux":  {"ansible_ssh_args": "-o ControlMaster=auto -o ForwardAgent=yes"},
		"unbalanced quote":     {"ansible_ssh_common_args": `-o "UserKnownHostsFile=/x`},
		"non-integer port":     {"ansible_port": "ssh"},
		"option value with sp": {"ansible_ssh_common_args": `-o "ProxyJump=a b"`},
	} {
		if _, err := sshTargetFromHostVars("ipa-1", vars); err == nil {
			t.Errorf("%s: accepted", name)
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

const golangTestFQDN = "ipa.example.test"
const golangTestPassword = "Sample-Admin-Password-9"

// fakeIPA answers login and JSON-RPC from the captured FreeIPA fixtures and
// records every method it is sent.
type fakeIPA struct {
	t       *testing.T
	srv     *httptest.Server
	ca      *x509.CertPool
	mu      sync.Mutex
	methods []string
	bodies  []string
	reader  string // the captured user given admins
	dir     string // the captured fixtures, absolute: tests chdir
}

func newFakeIPA(t *testing.T, reader string) *fakeIPA {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test IPA CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: golangTestFQDN}, DNSNames: []string{golangTestFQDN},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, _ := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "internal", "freeiparpc", "testdata"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIPA{t: t, ca: x509.NewCertPool(), reader: reader, dir: dir}
	f.ca.AddCert(caCert)
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIPA) fixture(name string) []byte {
	data, err := os.ReadFile(filepath.Join(f.dir, name+".json"))
	if err != nil {
		f.t.Error(err)
	}
	return data
}

func (f *fakeIPA) serve(w http.ResponseWriter, r *http.Request) {
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(r.Body)
	f.mu.Lock()
	f.bodies = append(f.bodies, body.String())
	f.mu.Unlock()
	if r.URL.Path == "/ipa/session/login_password" {
		http.SetCookie(w, &http.Cookie{Name: "ipa_session", Value: "fake-session-cookie-value", Path: "/ipa"})
		w.WriteHeader(http.StatusOK)
		return
	}
	var req struct {
		Method string `json:"method"`
		Params []any  `json:"params"`
	}
	_ = json.Unmarshal(body.Bytes(), &req)
	opts, _ := req.Params[1].(map[string]any)
	f.mu.Lock()
	f.methods = append(f.methods, req.Method)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case req.Method == "ping":
		_, _ = w.Write(f.fixture("ping"))
	case req.Method == "user_find" && opts["preserved"] == true:
		_, _ = w.Write(f.fixture("user-find-no-match"))
	case req.Method == "user_find":
		_, _ = w.Write(f.withAdmins(f.fixture("user-find-states")))
	case req.Method == "group_find":
		_, _ = w.Write(f.fixture("group-find-no-match"))
	case req.Method == "session_logout":
		_, _ = w.Write([]byte(`{"result":{"result":null},"error":null,"id":0,"principal":"admin@EXAMPLE.TEST","version":"4.13.4"}`))
	default:
		f.t.Errorf("unexpected method %s", req.Method)
		w.WriteHeader(http.StatusBadRequest)
	}
}

// withAdmins makes the captured reader a member of admins (spec §9 K4
// replaces this with a real admin entry once captured).
func (f *fakeIPA) withAdmins(data []byte) []byte {
	var env map[string]any
	_ = json.Unmarshal(data, &env)
	for _, e := range env["result"].(map[string]any)["result"].([]any) {
		u := e.(map[string]any)
		if u["uid"].([]any)[0] == f.reader {
			u["memberof_group"] = append(u["memberof_group"].([]any), "admins")
		}
	}
	out, _ := json.Marshal(env)
	return out
}

type fakeGolangDialer struct {
	f      *fakeIPA
	target sshdial.Target
}

func (d *fakeGolangDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", d.f.srv.Listener.Addr().String())
}
func (d *fakeGolangDialer) FQDN(context.Context) (string, error)       { return golangTestFQDN, nil }
func (d *fakeGolangDialer) CA(context.Context) (*x509.CertPool, error) { return d.f.ca, nil }

// golangWorkspace writes an inventory with one freeipa-server host, a
// plaintext vault vars file and the roster, and fakes ansible-inventory
// and ansible --list-hosts for it.
func golangWorkspace(t *testing.T, rosterDoc string, groups map[string][]string) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = "" })
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, ".vault"), 0o700))
	vault := map[string]string{}
	for _, key := range inventory.ExpectedVaultKeysForRoles([]string{"freeipa-server"}) {
		vault[key] = "sample-value-for-" + key
	}
	vault["ipa_admin_password"] = golangTestPassword
	vaultYAML, _ := yaml.Marshal(vault)
	must(os.WriteFile(filepath.Join(dir, ".vault", "main.yaml"), vaultYAML, 0o600))
	must(os.WriteFile(filepath.Join(dir, ".vault", "ipa-identity.yaml"), []byte(rosterDoc), 0o600))
	must(os.WriteFile(filepath.Join(dir, "inventory.yml"), []byte("all:\n  hosts:\n    ipa-1: {}\n"), 0o600))
	hostvars := map[string]any{"ipa-1": map[string]any{
		"freeipa_roster_file": ".vault/ipa-identity.yaml",
		"ansible_host":        "192.0.2.10",
		"ansible_user":        "root",
	}}
	inv := map[string]any{"_meta": map[string]any{"hostvars": hostvars}, "freeipa-server": map[string]any{"hosts": []string{"ipa-1"}}}
	for g, hosts := range groups {
		inv[g] = map[string]any{"hosts": hosts}
	}
	invJSON, _ := json.Marshal(inv)
	bin := t.TempDir()
	must(os.WriteFile(filepath.Join(bin, "ansible-inventory"), []byte("#!/bin/sh\ncat <<'EOF'\n"+string(invJSON)+"\nEOF\n"), 0o755))
	must(os.WriteFile(filepath.Join(bin, "ansible"), []byte("#!/bin/sh\nprintf '  hosts (1):\\n    ipa-1\\n'\n"), 0o755))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

// captureRoster declares the captured users as they are, with p1-self as
// the reading admin.
const captureRoster = `schema_version: 3
freeipa:
  admin: {principal: p1-self}
users:
  - {name: p1-keys, first: P1, last: Keys, display_name: P1 Keys, login_shell: /bin/sh}
  - {name: p1-nokeys, first: P1, last: NoKeys, display_name: P1 NoKeys, login_shell: /bin/sh}
  - {name: p1-nopw, first: P1, last: NoPw, display_name: P1 NoPw, login_shell: /bin/sh}
  - {name: p1-off, first: P1, last: "Off", display_name: P1 Off, login_shell: /bin/sh, state: disabled}
  - {name: p1-reset, first: P1, last: Reset, display_name: P1 Reset, login_shell: /bin/sh}
  - {name: p1-self, first: P1, last: Self, display_name: P1 Self, login_shell: %s}
`

func runGolangPreview(t *testing.T, args ...string) (string, error) {
	t.Helper()
	prev := []any{reconcileEngineFlag, reconcilePlanOutFlag, reconcilePreviewOnlyFlag, reconcileForceFlag, reconcileComponentFlags, reconcileDirFlag, reconcileInventoryFlag, reconcileTimeoutFlag, stageFlag, stagingAttestedHoursFlag, limitFlag, reconcileActionsPath}
	t.Cleanup(func() {
		reconcileEngineFlag, reconcilePlanOutFlag = prev[0].(string), prev[1].(string)
		reconcilePreviewOnlyFlag, reconcileForceFlag = prev[2].(bool), prev[3].(bool)
		reconcileComponentFlags, _ = prev[4].([]string)
		reconcileDirFlag, reconcileInventoryFlag, reconcileTimeoutFlag = prev[5].(string), prev[6].(string), prev[7].(string)
		stageFlag, stagingAttestedHoursFlag, limitFlag, reconcileActionsPath = prev[8].(string), prev[9].(string), prev[10].(string), prev[11].(string)
	})
	reconcileEngineFlag, reconcilePreviewOnlyFlag, reconcileForceFlag = "golang", true, false
	reconcileComponentFlags = []string{"freeipa-identity"}
	reconcileDirFlag, reconcileInventoryFlag, reconcileTimeoutFlag = ".", "inventory.yml", "2m"
	stageFlag, stagingAttestedHoursFlag, limitFlag, reconcileActionsPath, reconcilePlanOutFlag = "", "", "", "", ""
	for i := 0; i+1 < len(args); i += 2 {
		switch args[i] {
		case "--plan-out":
			reconcilePlanOutFlag = args[i+1]
		case "--stage":
			stageFlag = args[i+1]
		}
	}
	var out bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&out)
	command.SetErr(&out)
	command.SetContext(context.Background())
	err := runReconcile(command, nil)
	return out.String(), err
}

func withFakeDialer(t *testing.T, f *fakeIPA) *[]sshdial.Target {
	t.Helper()
	var targets []sshdial.Target
	prev := newGolangDialer
	newGolangDialer = func(target sshdial.Target) golangDialer {
		targets = append(targets, target)
		return &fakeGolangDialer{f: f, target: target}
	}
	t.Cleanup(func() { newGolangDialer = prev })
	return &targets
}

// From the reconcile command to a TLS FreeIPA answering captured fixtures:
// a roster matching the capture plans nothing, sends no write and leaks
// neither password nor cookie (spec §2, §6.1, §10.1).
func TestReconcileGolangPreviewEndToEnd(t *testing.T) {
	f := newFakeIPA(t, "p1-self")
	targets := withFakeDialer(t, f)
	dir := golangWorkspace(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1), nil)
	planPath := filepath.Join(dir, "plan.json")

	out, err := runGolangPreview(t, "--plan-out", planPath)
	if err != nil {
		t.Fatalf("preview: %v\n%s", err, out)
	}
	if !strings.Contains(out, "沒有任何寫入") || !strings.Contains(out, "--engine golang") {
		t.Fatalf("output:\n%s", out)
	}
	if len(*targets) != 1 || (*targets)[0].Host != "192.0.2.10" || (*targets)[0].User != "root" {
		t.Fatalf("ssh targets = %+v", *targets)
	}
	f.mu.Lock()
	methods := slices.Clone(f.methods)
	bodies := strings.Join(f.bodies, "\n")
	f.mu.Unlock()
	if !slices.Equal(methods, []string{"ping", "user_find", "user_find", "group_find", "session_logout"}) {
		t.Fatalf("methods = %v", methods)
	}
	if !strings.Contains(bodies, golangTestPassword) {
		t.Fatal("the login never carried the password")
	}
	info, err := os.Stat(planPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("plan file: %v %v", info, err)
	}
	plan, _ := os.ReadFile(planPath)
	var doc struct {
		Schema, Result, Scope string
		Engine                struct{ Name string }
		Operations            []any
		Stats                 struct{ Writes, Reads int }
	}
	if err := json.Unmarshal(plan, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != "pilot.identity-plan/v1" || doc.Result != "ok" || doc.Scope != "users-groups" || doc.Engine.Name != "golang" || len(doc.Operations) != 0 || doc.Stats.Writes != 0 || doc.Stats.Reads != 4 {
		t.Fatalf("plan = %s", plan)
	}
	for _, secret := range []string{golangTestPassword, "fake-session-cookie-value"} {
		if strings.Contains(out, secret) || strings.Contains(string(plan), secret) {
			t.Fatalf("%q leaked into the output or the plan", secret)
		}
	}
	if _, err := runGolangPreview(t, "--plan-out", planPath); err == nil || !strings.Contains(err.Error(), "已存在") {
		t.Fatalf("an existing --plan-out was overwritten: %v", err)
	}
}

func TestReconcileGolangPreviewPlansAChange(t *testing.T) {
	f := newFakeIPA(t, "p1-self")
	withFakeDialer(t, f)
	golangWorkspace(t, strings.Replace(captureRoster, "%s", "/bin/bash", 1), nil)
	out, err := runGolangPreview(t)
	if err != nil {
		t.Fatalf("preview: %v\n%s", err, out)
	}
	if !strings.Contains(out, "計畫：1 個寫入") || !strings.Contains(out, "user.update") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestReconcileGolangPreviewBlockedExitCode(t *testing.T) {
	f := newFakeIPA(t, "p1-self")
	withFakeDialer(t, f)
	// p1-self's captured uidnumber is not 1: changing it is blocked.
	golangWorkspace(t, strings.Replace(captureRoster, "%s", "/bin/sh, uid: 1", 1), nil)
	out, err := runGolangPreview(t)
	var coded ExitCoder
	if !errors.As(err, &coded) || coded.ExitCode() != golangPreviewBlockedExitCode {
		t.Fatalf("err = %v, want exit code %d\n%s", err, golangPreviewBlockedExitCode, out)
	}
	if !strings.Contains(out, "uid_or_gid_change") {
		t.Fatalf("output:\n%s", out)
	}
}

// Failures before the tunnel: nothing is dialed.
func TestReconcileGolangPreviewFailsBeforeConnecting(t *testing.T) {
	for _, tc := range []struct {
		name   string
		roster string
		groups map[string][]string
		args   []string
		want   string
	}{
		{name: "prod host without --stage prod", roster: strings.Replace(captureRoster, "%s", "/bin/sh", 1), groups: map[string][]string{"prod": {"ipa-1"}}, want: "prod group"},
		{name: "legacy roster", roster: "users: []\n", want: "no schema_version"},
		{name: "templated admin password", roster: strings.Replace(captureRoster, "%s", "/bin/sh", 1), want: "Jinja template"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeIPA(t, "p1-self")
			targets := withFakeDialer(t, f)
			golangWorkspace(t, tc.roster, tc.groups)
			if tc.name == "templated admin password" {
				if err := os.WriteFile(filepath.Join(".vault", "main.yaml"), []byte("ipa_admin_password: \"{{ lookup('env', 'X') }}\"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			out, err := runGolangPreview(t, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q\n%s", err, tc.want, out)
			}
			if len(*targets) != 0 || len(f.methods) != 0 {
				t.Fatalf("connected anyway: %v %v", *targets, f.methods)
			}
		})
	}
}
