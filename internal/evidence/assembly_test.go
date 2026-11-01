package evidence

import (
	"bytes"
	"debug/buildinfo"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This actual native counterexample distinguishes a compiler/header dependency
// from a membership-only assertion: both binaries build, and their SHA differs.
func TestPinnedControllerAssemblyClosure(t *testing.T) {
	if os.Getenv("PILOT_REQUIRE_CONTROLLER_TESTS") != "1" {
		t.Skip("explicit Docker controller integration not requested")
	}
	root := t.TempDir()
	copyControllerProfile(t, root)
	writeClosureFile(t, root, "go.mod", "module github.com/kjelly/pilot\n\ngo 1.26.8\n")
	writeClosureFile(t, root, "go.sum", "")
	writeClosureFile(t, root, "cmd/pilot/main.go", "package main\nimport \"fmt\"\nfunc assemblyValue() int\nfunc main() {fmt.Println(assemblyValue())}\n")
	writeClosureFile(t, root, "cmd/pilot/value.h", "#define VALUE 225\n")
	writeClosureFile(t, root, "cmd/pilot/value.s", "#include \"textflag.h\"\n#include \"value.h\"\nTEXT ·assemblyValue(SB), NOSPLIT, $0-8\n MOVQ $VALUE, ret+0(FP)\n RET\n")
	exe := filepath.Join(t.TempDir(), "pilot")
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", exe, "./cmd/pilot")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOAMD64=v1", "GOWORK=off", "GOENV=off", "GOFLAGS=", "GOTOOLCHAIN=local")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native header fixture build: %v %s", err, out)
	}
	if out, err := exec.Command(exe).CombinedOutput(); err != nil || string(out) != "225\n" {
		t.Fatalf("actual consumed header225: %v %s", err, out)
	}
	var log bytes.Buffer
	c, err := NewPinnedController(root, exe, &log)
	if err != nil {
		t.Fatalf("native constructor: %v %s", err, log.String())
	}
	defer c.Close()
	var first, second, diagnostics bytes.Buffer
	if err := c.execute("go-rebuild", nil, &first, &diagnostics); err != nil {
		t.Fatalf("pinned header225 rebuild: %v %s", err, diagnostics.String())
	}
	if strings.TrimSpace(first.String()) != c.proof.BinarySHA256 {
		t.Fatal("native positive source/binary precondition failed")
	}
	writeClosureFile(t, root, "cmd/pilot/value.h", "#define VALUE 226\n")
	if err := c.execute("go-rebuild", nil, &second, &diagnostics); err != nil {
		t.Fatalf("pinned header226 rebuild: %v %s", err, diagnostics.String())
	}
	if first.String() == second.String() || len(strings.TrimSpace(second.String())) != 64 {
		t.Fatal("existing consumed header change did not change native binary")
	}
	writeClosureFile(t, root, "cmd/pilot/value.h", "#define VALUE 225\n")
	r := &resolver{files: map[string]*File{}, patterns: map[string]bool{}}
	c.proof.Build = &ControllerBuild{SourcesSHA256: "old incomplete proof"}
	err = c.addGoSourceClosure(r)
	if err == nil || !strings.Contains(err.Error(), "candidate assembly/system objects") || len(r.files) != 0 || c.proof.Build != nil {
		t.Fatalf("consumed header omission must refuse candidate assembly atomically: err=%v files=%v build=%+v", err, r.files, c.proof.Build)
	}
	t.Logf("native header225 SHA=%s header226 SHA=%s; both pinned builds passed, candidate assembly refused atomically", strings.TrimSpace(first.String()), strings.TrimSpace(second.String()))
	nativeModuleAssemblyAudit(t, c.image)
}

// Execute the production audit definitions in the real pinned Python/SDK. The
// small module fixtures isolate its grammar/search-path oracle; go mod verify
// and the actual pilot module graph have separate whole-controller controls.
func nativeModuleAssemblyAudit(t *testing.T, image string) {
	t.Helper()
	program := `
import ast, pathlib, os, re, stat, tempfile, json
source=pathlib.Path('/opt/pilot-controller/launch.py').read_text()
nodes=[node for node in ast.parse(source).body if isinstance(node,ast.FunctionDef)]
exec(compile(ast.Module(body=nodes,type_ignores=[]),'native-production-audit','exec'))
with tempfile.TemporaryDirectory() as temp:
 root=pathlib.Path(temp); cache=root/'modcache'; module=cache/'example.org/dep@v1.0.0'; module.mkdir(parents=True)
 package=module/'pkg'; package.mkdir()
 asm=package/'value.s'
 def listing():
  return [{'Dir':str(package),'Module':{'Dir':str(module),'Sum':'h1:synthetic-grammar-fixture'},'SFiles':['value.s']}]
 def check(label,raw,setup=lambda p:None,accepted=False):
  asm.write_bytes(raw); p=listing(); setup(p[0])
  try: audit_module_assembly(p,str(cache))
  except (ValueError,OSError):
   if accepted: raise AssertionError('supported module literal subset refused: '+label)
  else:
   if not accepted: raise AssertionError('unsafe module assembly admitted: '+label)
   assert p[0]['ControllerAssembly']=='verified-module-literal-includes/v1'
 cases=[('plain',b'TEXT foo(SB), $0\n',True),('literal',b'#include "textflag.h"\n',True),('spaces',b'  #include "funcdata.h"  \n',True),
 ('relative',b'#include "../value.h"\n',False),('absolute',b'#include "/tmp/value.h"\n',False),('nested',b'#include "nested/value.h"\n',False),
 ('arbitrary-extension',b'#include "value.data"\n',False),('macro',b'#define HEADER "textflag.h"\n#include HEADER\n',False),
 ('conditional',b'#ifdef CUSTOM\n#include "textflag.h"\n#endif\n',False),('comment',b'// #include "value.h"\n',False),
 ('comment-obfuscated',b'#/**/include "textflag.h"\n',False),('escaped',b'#include "text\\x66lag.h"\n',False),
 ('continuation',b'#include \\\n"textflag.h"\n',False),('trailing-comment',b'#include "textflag.h" // comment\n',False),
 ('tab',b'\t#include "textflag.h"\n',False),('cr',b'#include "textflag.h"\r\n',False),('formfeed',b'#include "textflag.h"\x0c',False),
 ('generated',b'#include "go_asm.h"\n',False),('missing',b'#include "missing.h"\n',False),('hash-string',b'DATA foo<>/8, $"#text"\n',False)]
 for label,raw,accepted in cases: check(label,raw,accepted=accepted)
 check('renamed-header',b'#include "textflag.h"\n',lambda p:p.update(HFiles=['textflag_linux_amd64.h']))
 check('system-object',b'',lambda p:p.update(SysoFiles=['value.syso']))
 check('wrong-module',b'',lambda p:p['Module'].update(Dir=str(root)))
 check('replacement',b'',lambda p:p['Module'].update(Replace={'Dir':str(module)}))
 check('unverified',b'',lambda p:p['Module'].update(Sum=''))
 shadow=package/'textflag.h'; shadow.write_text('#define HIDDEN 225\n')
 check('package-shadow',b'#include "textflag.h"\n'); shadow.unlink()
 outside=root/'outside.s'; outside.write_text('TEXT foo(SB),$0\n'); asm.unlink(); asm.symlink_to(outside)
 try: audit_module_assembly(listing(),str(cache))
 except ValueError: pass
 else: raise AssertionError('symlink module assembly admitted')
 asm.unlink()
 headers=root/'headers'; headers.mkdir()
 for label,raw in [('nested-include',b'#include "value.h"\n'),('macro-hash',b'#define HEADER # include\n'),('continued-hash',b'#define X \\\n // #include "value.h"\n')]:
  (headers/'one.h').write_bytes(raw)
  try: audit_sdk_headers(str(headers))
  except ValueError: pass
  else: raise AssertionError('unclosed SDK header admitted: '+label)
 print(json.dumps({'module_cases':len(cases)+7,'sdk_negative_cases':3,'native_sdk_headers':len(list(pathlib.Path('/opt/go/pkg/include').iterdir()))}))
`
	cmd := exec.Command("docker", "run", "--rm", "-i", "--read-only", "--network", "none", "--user", "1000:1000", "--cap-drop", "ALL", "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777", "--entrypoint", "/usr/bin/python3", image, "-I", "-")
	cmd.Stdin = strings.NewReader(program)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("native module assembly audit oracle: %v %s", err, out)
	}
	t.Logf("production native module assembly grammar/search-path audit: %s", out)
}

func TestPinnedControllerIgnoredAssemblyActivation(t *testing.T) {
	if os.Getenv("PILOT_REQUIRE_CONTROLLER_TESTS") != "1" {
		t.Skip("explicit Docker controller integration not requested")
	}
	root := t.TempDir()
	copyControllerProfile(t, root)
	writeClosureFile(t, root, "go.mod", "module github.com/kjelly/pilot\n\ngo 1.26.8\n")
	writeClosureFile(t, root, "go.sum", "")
	writeClosureFile(t, root, "cmd/pilot/main.go", "package main\nimport \"fmt\"\nvar asmValue uint64\nfunc main(){fmt.Println(asmValue)}\n")
	inactive := "//go:build never\n\nDATA ·asmValue+0(SB)/8, $226\nGLOBL ·asmValue(SB), 8, $8\n"
	writeClosureFile(t, root, "cmd/pilot/value.s", inactive)
	exe := filepath.Join(t.TempDir(), "pilot")
	build := func() {
		t.Helper()
		cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", exe, "./cmd/pilot")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOAMD64=v1", "GOWORK=off", "GOENV=off", "GOFLAGS=", "GOTOOLCHAIN=local")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("ignored-source fixture native build: %v %s", err, out)
		}
	}
	build()
	if out, err := exec.Command(exe).CombinedOutput(); err != nil || string(out) != "0\n" {
		t.Fatalf("inactive assembly precondition: %v %s", err, out)
	}
	var log bytes.Buffer
	c, err := NewPinnedController(root, exe, &log)
	if err != nil {
		t.Fatalf("native ignored-source constructor: %v %s", err, log.String())
	}
	defer c.Close()
	r := &resolver{files: map[string]*File{}, patterns: map[string]bool{}}
	if err := c.addGoSourceClosure(r); err != nil {
		t.Fatalf("pure-Go graph with ignored native file: %v %s", err, log.String())
	}
	before := r.files["cmd/pilot/value.s"]
	if before == nil || before.SHA256 != digestBytes([]byte(inactive)) || !r.patterns["cmd/pilot/*"] {
		t.Fatal("existing ignored native source bytes/membership were omitted")
	}
	first := c.proof.Build.RebuiltBinarySHA256
	active := strings.Replace(inactive, "never", "linux && amd64", 1)
	writeClosureFile(t, root, "cmd/pilot/value.s", active)
	var rebuilt, diagnostics bytes.Buffer
	if err := c.execute("go-rebuild", nil, &rebuilt, &diagnostics); err != nil {
		t.Fatalf("activated assembly pinned build: %v %s", err, diagnostics.String())
	}
	if first == strings.TrimSpace(rebuilt.String()) {
		t.Fatal("same-path build-tag activation did not change native binary")
	}
	after, err := rawClosureFile(root, filepath.Join(root, "cmd/pilot/value.s"), "")
	if err != nil || before.Blob == after.Blob {
		t.Fatal("same membership activation was not content-bound")
	}
	r = &resolver{files: map[string]*File{}, patterns: map[string]bool{}}
	if err := c.addGoSourceClosure(r); err == nil || !strings.Contains(err.Error(), "candidate assembly/system objects") || c.proof.Build != nil || len(r.files) != 0 {
		t.Fatalf("activated assembly did not atomically refuse: %v", err)
	}
	// The old executable remains the controller identity; independently run a new
	// host SDK build solely to demonstrate the externally changed program value.
	build()
	if out, err := exec.Command(exe).CombinedOutput(); err != nil || string(out) != "226\n" {
		t.Fatalf("activated assembly actual behavior: %v %s", err, out)
	}
	t.Logf("existing ignored value.s: native stdout0->226, pinned SHA%s->%s, unchanged path but different bound blob%s->%s", first, strings.TrimSpace(rebuilt.String()), before.Blob, after.Blob)
}

// A CGO=0 executable can still import an arbitrary shared object. Keep its
// bytes constant while changing that library, and observe actual loader output.
func TestGoOnlyDynamicLoaderCannotCertifyStaticClosure(t *testing.T) {
	if os.Getenv("PILOT_REQUIRE_CONTROLLER_TESTS") != "1" {
		t.Skip("explicit native compiler integration not requested")
	}
	root := t.TempDir()
	writeClosureFile(t, root, "go.mod", "module github.com/kjelly/pilot\n\ngo 1.26.8\n")
	writeClosureFile(t, root, "cmd/pilot/main.go", "package main\nfunc main(){println(\"go-main\")}\n")
	exe := filepath.Join(root, "pilot")
	build := func() {
		t.Helper()
		cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", exe, "./cmd/pilot")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOAMD64=v1", "GOWORK=off", "GOENV=off", "GOFLAGS=", "GOTOOLCHAIN=local")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("native dynamic-import fixture build: %v %s", err, out)
		}
	}
	build()
	if err := validateStaticPilotELF(exe); err != nil {
		t.Fatalf("actual static Go positive refused: %v", err)
	}
	writeClosureFile(t, root, "cmd/pilot/main.go", "package main\n//go:cgo_import_dynamic _ _ \"./libprobe.so\"\nfunc main(){println(\"go-main\")}\n")
	build()
	info, err := buildinfo.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateBuildInfo(info); err != nil {
		t.Fatalf("native CGO0 BuildInfo precondition failed: %v", err)
	}
	binarySHA, err := SHA256File(exe)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"225", "226"} {
		cc := exec.Command("cc", "-shared", "-fPIC", "-x", "c", "-", "-o", filepath.Join(root, "libprobe.so"))
		cc.Stdin = strings.NewReader("#include <unistd.h>\n__attribute__((constructor)) static void report(void){write(2,\"lib" + value + "\\n\",7);}\n")
		if out, err := cc.CombinedOutput(); err != nil {
			t.Fatalf("native shared-object fixture: %v %s", err, out)
		}
		cmd := exec.Command(exe)
		cmd.Dir = root
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		out, err := cmd.CombinedOutput()
		if err != nil || string(out) != "lib"+value+"\ngo-main\n" {
			t.Fatalf("actual native-loader behavior %s: %v %s", value, err, out)
		}
		sum, err := SHA256File(exe)
		if err != nil || sum != binarySHA {
			t.Fatal("dynamic-loader counterexample changed executable bytes")
		}
	}
	if err := validateStaticPilotELF(exe); err == nil || !strings.Contains(err.Error(), "dynamic pilot ELF") {
		t.Fatalf("CGO0 dynamic native-loader executable accepted: %v", err)
	}
	c := &Controller{binary: exe, proof: ControllerProof{Build: &ControllerBuild{SourcesSHA256: "old proof"}}}
	r := &resolver{files: map[string]*File{}, patterns: map[string]bool{}}
	if err := c.addGoSourceClosure(r); err == nil || !strings.Contains(err.Error(), "dynamic pilot ELF") || c.proof.Build != nil || len(r.files) != 0 {
		t.Fatalf("native-loader closure refusal not atomic: %v", err)
	}
	t.Logf("actual CGO0 constant-binary SHA%s library225->226 changed stderr; dynamic ELF refused before source listing/cache", binarySHA)
}
