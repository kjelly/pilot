package evidence

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func copyControllerProfile(t *testing.T, root string) {
	t.Helper()
	for _, name := range controllerProfileFiles {
		raw, err := os.ReadFile(filepath.Join("../..", ControllerProfile, name))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, ControllerProfile, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
}
func TestPinnedControllerNativeBoundary(t *testing.T) {
	if os.Getenv("PILOT_REQUIRE_CONTROLLER_TESTS") != "1" {
		t.Skip("explicit Docker controller integration not requested")
	}
	root := t.TempDir()
	copyControllerProfile(t, root)
	hostile := filepath.Join(root, "hostile")
	if err := os.MkdirAll(hostile, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostile, "ansible.py"), []byte("raise Exception('host contamination')\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PYTHONPATH", hostile)
	t.Setenv("ANSIBLE_CONFIG", filepath.Join(hostile, "ansible.cfg"))
	t.Setenv("ANSIBLE_ACTION_PLUGINS", hostile)
	writeClosureFile(t, root, "go.mod", "module github.com/kjelly/pilot\n\ngo 1.26.8\n")
	writeClosureFile(t, root, "go.sum", "")
	writeClosureFile(t, root, "cmd/pilot/main.go", "package main\nfunc main() {}\n")
	exe := filepath.Join(t.TempDir(), "pilot")
	buildCommand := exec.Command("go", "build", "-buildvcs=false", "-o", exe, "./cmd/pilot")
	buildCommand.Dir = root
	buildCommand.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off", "GOENV=off", "GOFLAGS=", "GOTOOLCHAIN=local")
	if output, err := buildCommand.CombinedOutput(); err != nil {
		t.Fatalf("build native synthetic identity fixture: %v %s", err, output)
	}
	var build bytes.Buffer
	c, err := NewPinnedController(root, exe, &build)
	if err != nil {
		t.Fatalf("native constructor: %v\n%s", err, build.String())
	}
	defer c.Close()
	key := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(key, []byte("synthetic native-parser key (no SSH invocation)"), 0600); err != nil {
		t.Fatal(err)
	}
	inv := filepath.Join(t.TempDir(), "inventory.yml")
	raw := "all:\n  children:\n    parent:\n      children:\n        evidence_nodes:\n          hosts:\n            native-probe:\n              ansible_connection: ssh\n              ansible_host: 192.0.2.1\n              ansible_user: ubuntu\n              ansible_port: 22\n              ansible_ssh_private_key_file: " + key + "\n"
	if err := os.WriteFile(inv, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareInventory(inv); err != nil {
		t.Fatal(err)
	}
	if !c.InventoryProven() || len(c.Inventory().Groups["parent"]) != 1 {
		t.Fatalf("actual native inventory ancestry not proved: inventory=%+v kind=%s", c.Inventory(), c.proof.InventoryKind)
	}
	writeClosureFile(t, root, "apply.yml", "- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.debug:\n        msg: literal\n")
	var stdout, stderr bytes.Buffer
	if err := c.Run("L1 syntax check", "ansible-playbook", []string{"apply.yml", "--syntax-check"}, &stdout, &stderr); err != nil {
		t.Fatalf("native syntax routing: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	closure, err := ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"apply.yml"}, Controller: c})
	if err != nil {
		t.Fatal(err)
	}
	if len(closure.Unresolved) != 0 || len(closure.External) != 0 {
		t.Fatalf("real native controlled literal scope incomplete: %+v", closure)
	}
	proof, err := c.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if proof.PreProbeSHA256 != proof.PostProbeSHA256 || proof.Steps.Syntax != 1 || !validNativeProbe(proof.NativeProbe) {
		t.Fatalf("actual routed proof invalid: %+v", proof)
	}
	t.Logf("actual image=%s config=%s native=%s/%s pre/post=%s routed=%+v", proof.ImageID, proof.ConfigSHA256, proof.NativeProbe.Ansible, proof.NativeProbe.Python, proof.PreProbeSHA256, proof.Steps)
	// Inventory-aware missing candidates, untouched examples, custom-code denial.
	writeClosureFile(t, root, "group_vars/unmatched.example.yml", "value: '{{ lookup(\"file\", \"unmatched\") }}'\n")
	closure, err = ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"apply.yml"}, Controller: c})
	if err != nil {
		t.Fatal(err)
	}
	if len(closure.Unresolved) != 0 {
		t.Fatal("unmatched example vars contaminated actual inventory scope")
	}
	expected := []string{"group_vars/all.yml", "group_vars/ungrouped.yml", "group_vars/parent.yml", "group_vars/evidence_nodes.yml", "host_vars/native-probe.yml"}
	for _, path := range expected {
		found := false
		for _, pattern := range closure.Patterns {
			if pattern == path {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing native vars candidate pattern %s", path)
		}
	}
	for _, path := range []string{"roles/custom/tasks/main.yml", "collections/custom.py", "ansible_collections/custom.py", "connection_plugins/ssh.py"} {
		writeClosureFile(t, root, path, "# custom controller input\n")
		after, err := ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"apply.yml"}, Controller: c})
		if err != nil {
			t.Fatal(err)
		}
		if len(after.Unresolved) == 0 {
			t.Fatalf("custom controller discovery falsely complete: %s", path)
		}
		if err := os.RemoveAll(filepath.Join(root, strings.Split(path, "/")[0])); err != nil {
			t.Fatal(err)
		}
	}
	// Verify the actual pinned Go tool rejects a modified extracted dependency,
	// using an owned cache copy rather than touching the shared module cache.
	privateCache := t.TempDir()
	module := "github.com/google/uuid"
	version := "v1.6.0"
	for _, relative := range []string{module + "@" + version, "cache/download/" + module + "/@v"} {
		dest := filepath.Join(privateCache, relative)
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.CopyFS(dest, os.DirFS(filepath.Join(c.moduleCache, relative))); err != nil {
			t.Fatal(err)
		}
	}
	writeClosureFile(t, root, "go.mod", "module github.com/kjelly/pilot\n\ngo 1.26.8\nrequire github.com/google/uuid v1.6.0\n")
	originalCache := c.moduleCache
	c.moduleCache = privateCache
	var verification bytes.Buffer
	if err := c.execute("go-verify", nil, &verification, &verification); err != nil {
		t.Fatalf("owned clean native module cache: %v %s", err, verification.String())
	}
	modified := filepath.Join(privateCache, module+"@"+version, "uuid.go")
	if err := os.WriteFile(modified, []byte("package uuid // deliberately modified owned cache\n"), 0644); err != nil {
		t.Fatal(err)
	}
	verification.Reset()
	if err := c.execute("go-verify", nil, &verification, &verification); err == nil || !strings.Contains(verification.String(), "dir has been modified") {
		t.Fatalf("native cache corruption not specifically refused: %v %s", err, verification.String())
	}
	bad, err := ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"apply.yml"}, Controller: c})
	if err != nil {
		t.Fatal(err)
	}
	guard := false
	for _, u := range bad.Unresolved {
		if u.Ref == "unproved Go build closure" && strings.Contains(u.Reason, "cache verification failed") {
			guard = true
		}
	}
	if !guard {
		t.Fatalf("native module verification failure was lost: %+v", bad.Unresolved)
	}
	t.Log("owned cache clean PASS; modified dependency specifically rejected by native go mod verify and closure guard")
	c.moduleCache = originalCache
	// The read-only root is real, and a changed profile invalidates postflight.
	if err := os.WriteFile(filepath.Join(root, ControllerProfile, "ansible.cfg"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Finalize(); err == nil || !strings.Contains(err.Error(), "input changed") {
		t.Fatalf("profile mutation was not rejected specifically: %v", err)
	}
}

func TestZeroControllerCannotClearAmbientRefusal(t *testing.T) {
	c, err := ComputeClosure(ClosureInput{Root: t.TempDir(), Controller: &Controller{}})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, u := range c.Unresolved {
		if u.Ref == "ambient Ansible plugin discovery" {
			found = true
		}
	}
	if !found {
		t.Fatal("unproved controller boolean/zero value cleared ambient boundary")
	}
}

func TestShortProtocolValuesSurviveOnlyTypedValidatedFields(t *testing.T) {
	for _, secret := range []string{"v1", "success", "pass", "git"} {
		t.Run(secret, func(t *testing.T) {
			source := []SecretSource{{Key: "api_token", value: secret}}
			rec := &Record{Schema: Schema, Outcome: "success", Candidate: Candidate{Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40), Source: "git"}, Steps: []Step{{Name: "L4 apply", Status: "pass", Note: secret}}, Verify: []VerifyResult{{VerifyVerdict: VerifyVerdict{Verdict: "PASS", Pass: 1}}}, Controller: &ControllerProof{Schema: ControllerSchema, InventoryKind: "pilot-rendered-ssh/v1"}, Operator: secret, Error: secret, Tooling: map[string]string{secret: secret}}
			if err := SanitizeRecord(rec, source); err != nil {
				t.Fatal(err)
			}
			raw, err := rec.Markdown(nil)
			if err != nil {
				t.Fatal(err)
			}
			roundtrip, err := ParseMachineBlock(raw)
			if err != nil {
				t.Fatalf("supported secret corrupted schema: %v", err)
			}
			if roundtrip.Schema != Schema || roundtrip.Outcome != "success" || roundtrip.Candidate.Source != "git" || roundtrip.Steps[0].Status != "pass" || roundtrip.Controller.Schema != ControllerSchema {
				t.Fatalf("short secret corrupted typed protocol: %+v", roundtrip)
			}
			if roundtrip.Operator != "<redacted>" || roundtrip.Error != "<redacted>" || roundtrip.Steps[0].Note != "<redacted>" || roundtrip.Tooling["<redacted>"] != "<redacted>" {
				t.Fatal("protocol exemption leaked into arbitrary metadata")
			}
			invalid := &Record{Schema: "custom-" + secret, Outcome: "custom-" + secret, Candidate: Candidate{Source: "custom-" + secret}, Steps: []Step{{Name: "custom-" + secret, Status: "custom-" + secret}}, Controller: &ControllerProof{Schema: "custom-" + secret}}
			if err := SanitizeRecord(invalid, source); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(invalid)
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range []string{invalid.Schema, invalid.Outcome, invalid.Candidate.Source, invalid.Steps[0].Name, invalid.Steps[0].Status, invalid.Controller.Schema} {
				if strings.Contains(value, secret) {
					t.Fatalf("invalid enum exempted secret: %s encoded=%s", value, encoded)
				}
			}
		})
	}
}

// This constructor/source-graph preflight uses the actual static pilot binary.
// It intentionally performs no SSH or VM mutation; full target chains run from
// the frozen candidate separately.
func TestPinnedControllerActualPilotGraph(t *testing.T) {
	if os.Getenv("PILOT_REQUIRE_CONTROLLER_TESTS") != "1" {
		t.Skip("explicit Docker controller integration not requested")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(t.TempDir(), "pilot")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", exe, "./cmd/pilot")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off", "GOENV=off", "GOFLAGS=", "GOOS=linux", "GOARCH=amd64", "GOAMD64=v1", "GOEXPERIMENT=", "GOFIPS140=off", "GOTOOLCHAIN=local")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("actual static pilot build: %v %s", err, out)
	}
	var log bytes.Buffer
	c, err := NewPinnedController(root, exe, &log)
	if err != nil {
		t.Fatalf("native actual constructor: %v %s", err, log.String())
	}
	defer c.Close()
	key := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(key, []byte("no SSH invocation"), 0600); err != nil {
		t.Fatal(err)
	}
	inv := filepath.Join(t.TempDir(), "inventory.yml")
	if err := os.WriteFile(inv, []byte("all:\n  hosts:\n    actual-probe:\n      ansible_connection: ssh\n      ansible_host: 192.0.2.1\n      ansible_user: ubuntu\n      ansible_port: 22\n      ansible_ssh_private_key_file: "+key+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareInventory(inv); err != nil {
		t.Fatal(err)
	}
	closure, err := ComputeClosure(ClosureInput{Root: root, Playbooks: []string{"internal/evidence/testdata/actual-run/reuse-apply.yml"}, Specs: []string{"internal/evidence/testdata/actual-run/reuse-spec.md"}, Controller: c})
	if err != nil {
		t.Fatal(err)
	}
	if len(closure.Unresolved) > 0 || len(closure.External) > 0 {
		t.Fatalf("actual pilot graph incomplete: unresolved=%+v external=%+v", closure.Unresolved, closure.External)
	}
	for _, path := range []string{"cmd/pilot/main.go", "internal/tools/verify_spec.go", "go.mod", "go.sum", "images/Dockerfile.pilot-target-ubuntu", "internal/detection/prompts/host-anomaly-v1.txt"} {
		found := false
		for _, f := range closure.Files {
			if f.Path == path {
				found = true
			}
		}
		if !found {
			t.Fatalf("actual executed/embedded source omitted: %s", path)
		}
	}
	for _, expected := range []string{"internal/tools/*.go", "internal/tools/*.s", "internal/tools/*.syso", "images/**", "internal/detection/**", "go.mod", "go.sum", "go.work", "vendor/**"} {
		found := false
		for _, pattern := range closure.Patterns {
			if pattern == expected {
				found = true
			}
		}
		if !found {
			t.Fatalf("actual package/embed/lock membership omitted: %s", expected)
		}
	}
	for _, pattern := range closure.Patterns {
		if pattern == "internal/**" || strings.HasPrefix(pattern, "internal/pr225_unused_import/") {
			t.Fatalf("unimported package was scoped: %s", pattern)
		}
	}
	proof, err := c.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if proof.Build == nil || proof.Build.GOAMD64 != "v1" || proof.PreProbeSHA256 != proof.PostProbeSHA256 {
		t.Fatalf("actual build proof invalid: %+v", proof)
	}
	rec := &Record{Closure: closure, Controller: proof}
	if err := SanitizeRecord(rec, []SecretSource{{Key: "api_token", value: "v1"}}, root); err != nil {
		t.Fatal(err)
	}
	if rec.Controller.Build.GOAMD64 != "v1" {
		t.Fatal("v1 secret corrupted validated Go tuning")
	}
	for _, f := range rec.Closure.Files {
		if strings.Contains(f.Path, "<redacted>") {
			t.Fatalf("valid bound source identity corrupted: %s", f.Path)
		}
	}
	t.Logf("actual pilot closure files=%d patterns=%d unresolved=0 external=0 build=%s/%s/%s cgo=%s image=%s", len(closure.Files), len(closure.Patterns), proof.Build.GoVersion, proof.Build.GOOS, proof.Build.GOAMD64, proof.Build.CGO, proof.ImageID)
	nativeInlineGrammarDifferential(t, func(program string, raw []byte) []byte {
		args := []string{"run", "--rm", "-i", "--read-only", "--entrypoint", "/usr/bin/python3", "--env", "PYTHONPATH=/usr/local/lib64/python3.14/site-packages:/usr/local/lib/python3.14/site-packages", c.image, "-P", "-c", program}
		cmd := exec.Command("docker", args...)
		cmd.Stdin = bytes.NewReader(raw)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("pinned native parser batch: %v %s", err, out)
		}
		return out
	})
}
