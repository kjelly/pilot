package spec

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// This harness keeps Ansible's actual tag selection, render, validation,
// fingerprint and freshness tasks. Only systemd is replaced by an adapter
// which starts/stops the real binary; SSH records actual daemon argv. A VM
// run covers systemd itself. In particular a successful config validator is
// not evidence that the running process has loaded that config.
func TestRegression_LoginProbeTaggedRuntime(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	t.Setenv("ANSIBLE_LOCAL_TEMP", filepath.Join(dir, "ansible-tmp"))
	t.Setenv("ANSIBLE_REMOTE_TEMP", filepath.Join(dir, "ansible-remote"))
	binary := filepath.Join(dir, "probe")
	artifact := filepath.Join(dir, "artifact")
	build := exec.Command("go", "build", "-o", artifact, "./cmd/pilot-login-probe")
	build.Dir = "../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	write := func(name, value string, mode os.FileMode) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(value), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	calls := write("calls", "", 0600)
	ssh := write("ssh", "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '"+calls+"'\nexit 0\n", 0700)
	shim := write("systemctl.py", `import json,os,signal,subprocess,sys,time,uuid
root=sys.argv[1]; action=sys.argv[2]
p=root+'/service.json'
try: state=json.load(open(p)); os.kill(state['pid'],0); active=True
except (FileNotFoundError,ProcessLookupError): state={}; active=False
if action=='show':
 if os.path.exists(root+'/race'):
  c=root+'/show-count'
  n=int(open(c).read())+1 if os.path.exists(c) else 1
  open(c,'w').write(str(n))
  if n==2:
   subprocess.run([sys.executable,__file__,root,'restarted'],check=True)
   state=json.load(open(p))
 print(state.get('invocation','') if active else ''); sys.exit(0)
if action=='is-active':
 print('active' if active else 'inactive');sys.exit(0 if active else 3)
if action=='reload':
 open(root+'/reloads','a').write('reload\n');sys.exit(0)
if action in ('restarted','stopped') and active:
 os.kill(state['pid'],signal.SIGCONT)
 os.kill(state['pid'],signal.SIGTERM)
 for _ in range(100):
  try:
   os.kill(state['pid'],0)
   if open('/proc/'+str(state['pid'])+'/stat').read().split()[2]=='Z': break
  except ProcessLookupError: break
  time.sleep(.01)
 else:
  os.kill(state['pid'],signal.SIGKILL)
 active=False
if action in ('started','restarted') and not active:
 log=open(root+'/daemon.log','ab')
 child=subprocess.Popen([root+'/probe','serve','--config',root+'/config.yml'],stdout=log,stderr=log,start_new_session=True)
 json.dump({'pid':child.pid,'invocation':str(uuid.uuid4())},open(p,'w'))
 if os.path.exists(root+'/freeze'):
  time.sleep(.1)
  os.kill(child.pid,signal.SIGSTOP)
`, 0600)
	ctl := func(action string) []any { return []any{"python3", shim, dir, action} }
	t.Cleanup(func() { _ = exec.Command("python3", shim, dir, "stopped").Run() })
	raw, err := os.ReadFile("../../playbooks/apply/login-probe-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	var tasks []map[string]any
	var collect func([]any)
	collect = func(all []any) {
		for _, item := range all {
			task := item.(map[string]any)
			name, _ := task["name"].(string)
			if block, ok := task["block"].([]any); ok {
				collect(block)
				continue
			}
			if !(strings.HasPrefix(name, "Step 4:") || strings.HasPrefix(name, "Step 5:") || strings.HasPrefix(name, "Step 8:") || strings.HasPrefix(name, "Step 9:") || strings.HasPrefix(name, "Step 10:") || strings.HasPrefix(name, "Step 11:") || strings.HasPrefix(name, "Step 12:") || strings.HasPrefix(name, "Step 13:") || strings.HasPrefix(name, "Step 14:") || strings.HasPrefix(name, "Step 15:") || strings.HasPrefix(name, "Runtime:")) {
				continue
			}
			for _, mod := range []string{"ansible.builtin.copy", "ansible.builtin.file"} {
				if args, ok := task[mod].(map[string]any); ok {
					delete(args, "owner")
					delete(args, "group")
					if content, ok := args["content"].(string); ok {
						args["content"] = strings.ReplaceAll(content, "ssh_binary: /usr/bin/ssh", "ssh_binary: "+ssh)
					}
					if name == "Step 10: render pilot-login-probe.service (dedicated account, read-only system, no listener)" {
						args["dest"] = "{{ login_probe_unit_path }}"
					}
				}
			}
			if args, ok := task["ansible.builtin.systemd"].(map[string]any); ok {
				action, _ := args["state"].(string)
				if action == "" {
					action = "reload"
				}
				delete(task, "ansible.builtin.systemd")
				task["ansible.builtin.command"] = map[string]any{"argv": ctl(action)}
			}
			if args, ok := task["ansible.builtin.command"].(map[string]any); ok {
				if argv, ok := args["argv"].([]any); ok && len(argv) > 0 && argv[0] == "systemctl" {
					args["argv"] = ctl(fmt.Sprint(argv[1]))
				}
			}
			if args, ok := task["ansible.builtin.assert"].(map[string]any); ok {
				if that, ok := args["that"].([]any); ok {
					for i, v := range that {
						if s, ok := v.(string); ok {
							that[i] = strings.ReplaceAll(s, ".stat.uid == 0", fmt.Sprintf(".stat.uid == %d", os.Getuid()))
						}
					}
				}
			}
			if strings.HasPrefix(name, "Step 15:") {
				// Same freshness predicate, a shorter negative-case deadline.
				task["retries"] = 3
				task["delay"] = 5
			}
			if args, ok := task["ansible.builtin.wait_for"].(map[string]any); ok {
				args["timeout"] = 2
			}
			tasks = append(tasks, task)
		}
	}
	collect(plays[0]["tasks"].([]any))
	vars := map[string]any{"login_probe_interval": "10s", "login_probe_connect_timeout": "1s", "login_probe_total_timeout": "2s", "login_probe_concurrency": 4, "login_probe_user": "old-canary", "login_probe_command": "/bin/true", "login_probe_target_list": []any{map[string]any{"name": "retired", "host": "retired.example.test", "port": 22}}, "login_probe_config_path": filepath.Join(dir, "config.yml"), "login_probe_bin_dest": binary, "login_probe_artifact_abs_path": artifact, "login_probe_ssh_config_path": filepath.Join(dir, "ssh_config"), "login_probe_unit_path": filepath.Join(dir, "probe.service"), "login_probe_textfile_path": filepath.Join(dir, "probe.prom"), "login_probe_textfile_dir": dir, "login_probe_service_user": "test-user", "login_probe_runtime_marker_path": filepath.Join(dir, ".applied-runtime")}
	data, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	vars["login_probe_artifact_sha256"] = fmt.Sprintf("%x", sha256.Sum256(data))
	write("ssh_config", "Host *\n", 0600)
	run := func(tag string) {
		t.Helper()
		out, ok := runLocalPlay(t, vars, tasks, "--tags", tag)
		if !ok {
			t.Fatalf("tag %s failed:\n%s", tag, out)
		}
	}
	waitFor := func(want string) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			b, _ := os.ReadFile(calls)
			if strings.Contains(string(b), want) {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		b, _ := os.ReadFile(calls)
		t.Fatalf("daemon never used %q; calls:\n%s", want, b)
	}
	run("all")
	waitFor("retired.example.test")
	invocation := func() string {
		t.Helper()
		out, err := exec.Command("python3", shim, dir, "show").Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}
	before := invocation()
	vars["login_probe_user"] = "new-canary"
	vars["login_probe_interval"] = "11s"
	vars["login_probe_target_list"] = []any{map[string]any{"name": "kept", "host": "kept.example.test", "port": 22}}
	run("C3")
	if invocation() == before {
		t.Fatal("C3 returned success without replacing the running daemon")
	}
	write("calls", "", 0600)
	waitFor("kept.example.test")
	b, _ := os.ReadFile(calls)
	if strings.Contains(string(b), "retired.example.test") || !strings.Contains(string(b), "new-canary") {
		t.Fatalf("wrong live SSH argv: %s", b)
	}
	log, _ := os.ReadFile(filepath.Join(dir, "daemon.log"))
	if !strings.Contains(string(log), `"interval":"11s"`) {
		t.Fatalf("daemon did not load new interval: %s", log)
	}
	before = invocation()
	run("C3")
	if invocation() != before {
		t.Fatal("unchanged C3 restarted an already converged daemon")
	}
	// Recreate a stopped/interrupted old deployment: new files on disk, but
	// no completed activation record. A no-change render must still recover.
	_ = os.Remove(vars["login_probe_runtime_marker_path"].(string))
	before = invocation()
	run("C3")
	if invocation() == before {
		t.Fatal("missing activation record did not recover unchanged disk state")
	}
	// Config already matches desired bytes but the old daemon still runs.
	configPath := vars["login_probe_config_path"].(string)
	disk, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	disk = []byte(strings.ReplaceAll(string(disk), "kept", "added"))
	if err := os.WriteFile(configPath, disk, 0600); err != nil {
		t.Fatal(err)
	}
	oldStat, _ := os.Stat(configPath)
	vars["login_probe_target_list"] = []any{map[string]any{"name": "added", "host": "added.example.test", "port": 22}}
	before = invocation()
	run("C3")
	if invocation() == before {
		t.Fatal("unchanged desired config did not recover stale runtime")
	}
	newStat, _ := os.Stat(configPath)
	if !oldStat.ModTime().Equal(newStat.ModTime()) {
		t.Fatal("fixture did not exercise unchanged config bytes")
	}
	write("calls", "", 0600)
	waitFor("added.example.test")
	b, _ = os.ReadFile(calls)
	if strings.Contains(string(b), "kept.example.test") {
		t.Fatalf("retired target remains live: %s", b)
	}

	// C1 must replace the executable in memory, including when old and new
	// binaries accept precisely the same on-disk configuration.
	upgraded := filepath.Join(dir, "upgraded")
	upgrade := exec.Command("go", "build", "-ldflags", "-X main.version=tagged-upgrade", "-o", upgraded, "./cmd/pilot-login-probe")
	upgrade.Dir = "../.."
	if out, err := upgrade.CombinedOutput(); err != nil {
		t.Fatalf("build upgrade %v %s", err, out)
	}
	data, err = os.ReadFile(upgraded)
	if err != nil {
		t.Fatal(err)
	}
	vars["login_probe_artifact_abs_path"] = upgraded
	vars["login_probe_artifact_sha256"] = fmt.Sprintf("%x", sha256.Sum256(data))
	before = invocation()
	run("C1")
	if invocation() == before {
		t.Fatal("C1 did not replace the executable in memory")
	}
	log, _ = os.ReadFile(filepath.Join(dir, "daemon.log"))
	if !strings.Contains(string(log), `"version":"tagged-upgrade"`) {
		t.Fatalf("live binary version is stale: %s", log)
	}

	// Each unit tag must actually reconcile + reload + restart, not just
	// leave correct text on disk. systemd property behavior is covered on VM.
	for _, tag := range []string{"C6", "C12"} {
		unit := vars["login_probe_unit_path"].(string)
		vars["login_probe_service_user"] = "service-user-" + strings.ToLower(tag)
		before = invocation()
		run(tag)
		if invocation() == before {
			t.Fatalf("%s did not activate the changed unit", tag)
		}
		unitBytes, _ := os.ReadFile(unit)
		if !strings.Contains(string(unitBytes), "NoNewPrivileges=yes") {
			t.Fatalf("%s unit not repaired", tag)
		}
	}

	// An external service restart invalidates InvocationID even with matching
	// hashes, so no previous process's successful health can be reused.
	if out, err := exec.Command("python3", shim, dir, "restarted").CombinedOutput(); err != nil {
		t.Fatalf("external restart %v %s", err, out)
	}
	before = invocation()
	run("C3")
	if invocation() == before {
		t.Fatal("external invocation reused prior activation health")
	}

	// A process replacement between the two show calls must not inherit
	// the prior process's completed health record on the no-restart path.
	write("race", "1", 0600)
	out, ok := runLocalPlay(t, vars, tasks, "--tags", "C3")
	if ok || !strings.Contains(out, "read the service invocation to validate") {
		t.Fatalf("mid-apply invocation replacement was accepted: %s", out)
	}
	_ = os.Remove(filepath.Join(dir, "race"))
	run("C3")

	// A stale but syntactically valid textfile cannot prove a new process
	// healthy. Freeze the replacement after its initial write, before the
	// post-restart generation snapshot; it produces no subsequent write.
	markerPath := vars["login_probe_runtime_marker_path"].(string)
	markerBefore, _ := os.ReadFile(markerPath)
	write("freeze", "1", 0600)
	_ = os.Remove(markerPath)
	out, ok = runLocalPlay(t, vars, tasks, "--tags", "C3")
	if ok || !strings.Contains(out, "wait for this daemon to rewrite") {
		t.Fatalf("frozen process inherited stale textfile health: %s", out)
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatal("failed freshness wrote an activation record")
	}
	_ = os.Remove(filepath.Join(dir, "freeze"))
	if err := os.WriteFile(markerPath, markerBefore, 0600); err != nil {
		t.Fatal(err)
	}
	run("C3")

	// C7 must still require real daemon metrics even when the activation
	// marker matches. An unrelated exporter preflight metric is insufficient.
	state, err := os.ReadFile(filepath.Join(dir, "service.json"))
	if err != nil {
		t.Fatal(err)
	}
	var serviceState struct {
		PID int `json:"pid"`
	}
	if err := json.Unmarshal(state, &serviceState); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(serviceState.PID, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(vars["login_probe_textfile_path"].(string))
	out, ok = runLocalPlay(t, vars, tasks, "--tags", "C7")
	_ = syscall.Kill(serviceState.PID, syscall.SIGCONT)
	if ok || !strings.Contains(out, "require the metrics textfile") {
		t.Fatalf("C7 accepted missing metrics on an unchanged activation: %s", out)
	}
}
