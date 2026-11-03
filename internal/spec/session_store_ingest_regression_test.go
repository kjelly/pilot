package spec

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func TestSessionStorePortContract(t *testing.T) {
	s, err := Parse("../../docs/verification/pilot-session-store.md")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Rows) != 27 {
		t.Fatalf("rows=%d, want 27", len(s.Rows))
	}
	for i, row := range s.Rows {
		if row.ID != fmt.Sprintf("SS%02d", i+1) || row.Expected != "0" {
			t.Errorf("unexpected row contract: %+v", row)
		}
		if row.ID == "SS02" {
			want := "python3 /usr/local/libexec/pilot-session-store-health.py --config /etc/pilot/session-store.yaml"
			if row.Command != want {
				t.Errorf("SS02 must check deployed endpoint: %q", row.Command)
			}
			if !NeedsBecome(row) {
				t.Error("SS02 needs root to inspect native process descriptors")
			}
		}
	}
	raw, err := os.ReadFile("../../contracts/pilot-session-store.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		GroupVars []struct {
			Name    string
			Default any
		} `yaml:"groupVars"`
		Endpoints []struct {
			Name string
			Port int
		}
	}
	if err := yaml.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range contract.GroupVars {
		if v.Name == "pilot_session_store_ingest_port" {
			found = true
			if v.Default != 18443 {
				t.Errorf("default=%v", v.Default)
			}
		}
	}
	if !found {
		t.Fatal("missing ingest port contract")
	}
	for _, ep := range contract.Endpoints {
		if ep.Name == "session-store-ingest" && ep.Port != 18443 {
			t.Errorf("endpoint port=%d", ep.Port)
		}
	}
	var plays []map[string]any
	raw, err = os.ReadFile("../../playbooks/apply/pilot-session-store-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	pre := plays[0]["pre_tasks"].([]any)
	seen := false
	for _, item := range pre {
		task := item.(map[string]any)
		if _, ok := task["ansible.builtin.script"]; ok {
			seen = true
			if task["check_mode"] != false || fmt.Sprint(task["tags"]) != "[always]" {
				t.Errorf("preflight must run under every selection and check mode: %v", task)
			}
		}
	}
	if !seen {
		t.Fatal("missing before-mutation port preflight")
	}
}

// This harness uses a real TLS listener, curl and kernel socket ownership.
// Only systemd discovery is replaced: recorded Ubuntu systemctl output has
// its MainPID replaced with the harness's actual listener-owning process.
// It does not prove native systemd availability or a full FreeIPA deployment.
func TestSessionStoreIngestHealth(t *testing.T) {
	for _, tool := range []string{"python3", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "configured.store.test"}, DNSNames: []string{"configured.store.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()
	port := strings.Split(srv.Listener.Addr().String(), ":")[1]
	certFile := filepath.Join(dir, "leaf.crt")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "session-store.yaml")
	if err := os.WriteFile(config, []byte(fmt.Sprintf("ingest:\n  listen_addr: \"0.0.0.0:%s\"\n  tls_cert_file: %s\n  tls_key_file: /not-read\n  signing_key_file: /not-read\nstorage:\n  key_id: test\n", port, certFile)), 0600); err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("testdata/session-store/systemctl-active-ssh.stdout")
	if err != nil {
		t.Fatal(err)
	}
	setState := func(pid int, active string) {
		lines := strings.Split(string(fixture), "\n")
		for i, line := range lines {
			if strings.HasPrefix(line, "MainPID=") {
				lines[i] = fmt.Sprintf("MainPID=%d", pid)
			}
			if strings.HasPrefix(line, "ActiveState=") {
				lines[i] = "ActiveState=" + active
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\ncat <<'STATE'\n"+strings.Join(lines, "\n")+"\nSTATE\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	helper := "../../playbooks/apply/files/pilot-session-store-health.py"
	run := func(args ...string) (string, error) {
		cmd := exec.Command("python3", append([]string{helper}, args...)...)
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "NO_PROXY=*")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	args := []string{"--config", config, "--ca-file", certFile}
	setState(os.Getpid(), "active")
	if out, err := run(args...); err != nil {
		t.Fatalf("configured identity/nondefault port: %v\n%s", err, out)
	}
	if out, err := run("--port", port); err != nil {
		t.Fatalf("healthy self reapply preflight: %v\n%s", err, out)
	}
	// A genuinely unbound port is allowed before a unit exists. This is the
	// native captured absent-unit response, not an invented systemctl format.
	absent, err := os.ReadFile("testdata/session-store/systemctl-absent.stdout")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\ncat <<'STATE'\n"+string(absent)+"STATE\n"), 0700); err != nil {
		t.Fatal(err)
	}
	free, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freePort := strings.Split(free.Addr().String(), ":")[1]
	if err := free.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := run("--port", freePort); err != nil {
		t.Fatalf("absent unit/free port preflight: %v %s", err, out)
	}
	// A discovery failure is a fault shim; even an unbound port cannot make
	// it pass, and the refusal must identify the failed query.
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\necho discovery-fault >&2\nexit 42\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if out, err := run("--port", freePort); err == nil || !strings.Contains(out, "systemctl discovery failed: discovery-fault") {
		t.Fatalf("probe error accepted/wrong reason: %v %s", err, out)
	}
	other := exec.Command("sleep", "60")
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Process.Kill(); _ = other.Wait() }()
	setState(other.Process.Pid, "active")
	// Independently prove that the wrong service is reachable over trusted TLS;
	// rejecting this case must come from ownership, not a failed TLS handshake.
	curl := exec.Command("curl", "--noproxy", "*", "--silent", "--show-error", "--cacert", certFile, "--resolve", "configured.store.test:"+port+":127.0.0.1", "--output", "/dev/null", "--write-out", "%{http_code}", "https://configured.store.test:"+port+"/v1/sessions/start")
	if out, err := curl.CombinedOutput(); err != nil || string(out) != "401" {
		t.Fatalf("independent trusted TLS oracle: %v %s", err, out)
	}
	for _, a := range [][]string{args, {"--port", port}} {
		if out, err := run(a...); err == nil || !strings.Contains(out, "does not own") {
			t.Fatalf("wrong owner accepted/wrong reason: %v %s", err, out)
		}
	}
	setState(os.Getpid(), "inactive")
	if out, err := run(args...); err == nil || !strings.Contains(out, "not active") {
		t.Fatalf("stopped service accepted/wrong reason: %v %s", err, out)
	}
	setState(os.Getpid(), "active")
	if out, err := run("--config", filepath.Join(dir, "missing.yaml")); err == nil || !strings.Contains(out, "missing.yaml") {
		t.Fatalf("missing config accepted/wrong reason: %v %s", err, out)
	}
	wrongCA := *tmpl
	wrongCA.SerialNumber = big.NewInt(78)
	wrongCA.Subject = pkix.Name{CommonName: "unrelated CA"}
	wrongDER, err := x509.CreateCertificate(rand.Reader, &wrongCA, &wrongCA, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	wrongCAFile := filepath.Join(dir, "wrong-ca.crt")
	if err := os.WriteFile(wrongCAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wrongDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := run("--config", config, "--ca-file", wrongCAFile); err == nil || !strings.Contains(out, "curl rc=60") {
		t.Fatalf("wrong CA accepted/wrong reason: %v %s", err, out)
	}
	// Mutation control: removing just the ownership predicate makes the
	// trusted wrong-service listener pass, so the oracle detects that defect.
	source, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(string(source), "if not listeners <= owned:", "if False:  # removed ownership predicate", 1)
	if mutated == string(source) {
		t.Fatal("ownership mutation did not apply")
	}
	helper = filepath.Join(dir, "mutated-health.py")
	if err := os.WriteFile(helper, []byte(mutated), 0600); err != nil {
		t.Fatal(err)
	}
	setState(other.Process.Pid, "active")
	if out, err := run(args...); err != nil {
		t.Fatalf("negative control must wrongly accept trusted other PID: %v %s", err, out)
	}
}
