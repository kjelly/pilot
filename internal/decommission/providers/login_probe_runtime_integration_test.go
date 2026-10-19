package providers_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/decommission"
	"github.com/kjelly/pilot/internal/decommission/providers"
	"go.yaml.in/yaml/v3"
)

type loginProbeRuntimeExecutor struct {
	run func(context.Context, ...string) (*ansible.Result, error)
}

func (r loginProbeRuntimeExecutor) Run(ctx context.Context, args ...string) (*ansible.Result, error) {
	return r.run(ctx, args...)
}

// The production provider, step executor and Ansible query observe a real
// daemon. Local systemd observation is adapted; native systemd and the full
// apply playbook are exercised separately on the disposable target chain.
func TestRegression_LoginProbeDecommissionRuntime(t *testing.T) {
	for _, tool := range []string{"ansible-playbook", "sudo"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
				t.Fatal(err)
			}
			t.Skip(err)
		}
	}
	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatal(err)
		}
		t.Skip("root-owned marker checks require passwordless sudo")
	}
	dir := t.TempDir()
	t.Setenv("ANSIBLE_LOCAL_TEMP", filepath.Join(dir, "ansible-local"))
	t.Setenv("ANSIBLE_REMOTE_TEMP", filepath.Join(dir, "ansible-remote"))
	write := func(name, text string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	config := filepath.Join(dir, "config.yml")
	binary := filepath.Join(dir, "probe")
	marker := filepath.Join(dir, ".applied-runtime")
	unit := write("probe.service", "[Service]\nExecStart="+binary+" serve --config "+config+"\n")
	build := exec.Command("go", "build", "-o", binary, "./cmd/pilot-login-probe")
	build.Dir = "../../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	calls := write("ssh-calls", "")
	ssh := write("ssh", "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '"+calls+"'\nexit 0\n")
	if err := os.Chmod(ssh, 0700); err != nil {
		t.Fatal(err)
	}
	state := write("service.json", `{"MainPID":"0","LoadState":"not-found","ActiveState":"inactive","SubState":"dead","UnitFileState":"","InvocationID":""}`)
	systemctl := write("systemctl", `#!/usr/bin/python3
import json,os,sys
state=json.load(open(os.path.join(os.path.dirname(__file__),'service.json')))
if os.path.exists(os.path.join(os.path.dirname(__file__),'show-error')): sys.exit(1)
if os.path.exists(os.path.join(os.path.dirname(__file__),'race')):
 state['InvocationID']=os.urandom(16).hex()
for key in ['MainPID','LoadState','ActiveState','SubState','UnitFileState','InvocationID']: print(key+'='+state[key])
`)
	if err := os.Chmod(systemctl, 0755); err != nil {
		t.Fatal(err)
	}
	var child *exec.Cmd
	stop := func() {
		if child == nil {
			return
		}
		_ = child.Process.Signal(syscall.SIGCONT)
		_ = child.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = child.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = child.Process.Kill()
			<-done
		}
		child = nil
	}
	t.Cleanup(stop)
	setState := func(inv string) {
		pid := "0"
		active, sub := "inactive", "dead"
		if child != nil {
			pid = fmt.Sprint(child.Process.Pid)
			active, sub = "active", "running"
		}
		data, _ := json.Marshal(map[string]string{"MainPID": pid, "LoadState": "loaded", "ActiveState": active, "SubState": sub, "UnitFileState": "enabled", "InvocationID": inv})
		if err := os.WriteFile(state, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	start := func() {
		stop()
		child = exec.Command(binary, "serve", "--config", config)
		log, err := os.OpenFile(filepath.Join(dir, "daemon.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		child.Stdout = log
		child.Stderr = log
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		_ = log.Close()
		id := make([]byte, 16)
		if _, err := rand.Read(id); err != nil {
			t.Fatal(err)
		}
		setState(hex.EncodeToString(id))
	}
	setConfig := func(retired bool) {
		targets := "  - {name: retained, host: retained.example.test}\n"
		if retired {
			targets += "  - {name: retired, host: retired.example.test}\n"
		}
		write("config.yml", fmt.Sprintf("interval: 10s\nconnect_timeout: 1s\ntotal_timeout: 2s\nssh_binary: %s\nssh_config: %s\ntextfile: %s\ntargets:\n%s", ssh, write("ssh_config", "Host *\n"), filepath.Join(dir, "metrics.prom"), targets))
	}
	stamp := func() {
		var values []string
		for _, p := range []string{binary, config, unit} {
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			values = append(values, fmt.Sprintf("%x", sha256.Sum256(data)))
		}
		var service map[string]string
		data, _ := os.ReadFile(state)
		_ = json.Unmarshal(data, &service)
		values = append(values, service["InvocationID"])
		input := write("marker-input", strings.Join(values, " ")+"\n")
		if out, err := exec.Command("sudo", "-n", "install", "-o", "root", "-g", "root", "-m", "0600", input, marker).CombinedOutput(); err != nil {
			t.Fatalf("marker: %v %s", err, out)
		}
	}
	raw, err := os.ReadFile("../../../playbooks/decommission/login-probe-target-query.yml")
	if err != nil {
		t.Fatal(err)
	}
	var query []any
	if err := yaml.Unmarshal(raw, &query); err != nil {
		t.Fatal(err)
	}
	query[0].(map[string]any)["environment"] = map[string]any{"PATH": dir + ":" + os.Getenv("PATH")}
	data, _ := yaml.Marshal(query)
	pb := write("query.yml", string(data))
	vars, _ := json.Marshal(map[string]any{"login_probe_config_path": config, "login_probe_query_config_path": config, "login_probe_bin_dest": binary, "login_probe_unit_path": unit, "login_probe_runtime_marker_path": marker, "ansible_connection": "local"})
	inv := write("inventory.yml", "all:\n  children:\n    login-probe:\n      hosts:\n        localhost: {}\n")
	applyCalls := 0
	runner := loginProbeRuntimeExecutor{run: func(ctx context.Context, args ...string) (*ansible.Result, error) {
		if args[0] == "apply.yml" {
			applyCalls++
			start()
			stamp()
			return &ansible.Result{}, nil
		}
		cmd := exec.CommandContext(ctx, "ansible-playbook", append(args, "-e", string(vars))...)
		out, err := cmd.CombinedOutput()
		rc := 0
		if err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				rc = exit.ExitCode()
			} else {
				return nil, err
			}
		}
		if rc == 0 && !strings.Contains(string(out), "changed=0") {
			t.Fatalf("read-only query reported a mutation: %s", out)
		}
		return &ansible.Result{Stdout: string(out), ExitCode: rc}, nil
	}}
	p := providers.NewLoginProbeTargetsProvider(providers.LoginProbeTargetsProviderConfig{Executor: runner, Inventory: inv, QueryPlaybook: pb, ApplyPlaybook: "apply.yml", ProbeHosts: []string{"localhost"}})
	ctx := context.Background()
	input := providers.InspectInput{HostName: "retired", FQDN: "retired.example.test"}
	setConfig(true)
	start()
	stamp()
	time.Sleep(time.Second)
	before, _ := os.ReadFile(calls)
	if !strings.Contains(string(before), "retired.example.test") {
		t.Fatalf("daemon did not probe retired host: %s", before)
	}
	setConfig(false) // simulate interruption after render, before restart
	insp, err := p.Inspect(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if !insp.Found {
		base, _ := os.ReadFile(calls)
		time.Sleep(11 * time.Second)
		after, _ := os.ReadFile(calls)
		delta := strings.TrimPrefix(string(after), string(base))
		if !strings.Contains(delta, "retired.example.test") {
			t.Fatalf("invalid counterexample, no later retired SSH attempt: %s", delta)
		}
		t.Fatalf("disk absence falsely reported clean while real daemon made another retired SSH attempt: %+v; calls=%s", insp, delta)
	}
	vs, err := p.Verify(ctx, providers.VerifyInput(input))
	if err != nil || len(vs) != 1 || !vs[0].Active {
		t.Fatalf("stale Verify: %v %v", vs, err)
	}
	steps, err := p.Plan(ctx, providers.PlanInput{HostName: input.HostName, FQDN: input.FQDN})
	if err != nil || len(steps) != 1 {
		t.Fatalf("Plan: %v %v", steps, err)
	}
	step, err := p.ExecutorForStep(steps[0])
	if err != nil {
		t.Fatal(err)
	}
	run := decommission.NewExecutor([]*decommission.ExecStep{decommission.NewExecStep("remove", p.ID(), steps[0].Action, step)})
	if err := run.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if applyCalls != 1 {
		t.Fatalf("runtime repair skipped: apply calls=%d", applyCalls)
	}
	vs, err = p.Verify(ctx, providers.VerifyInput(input))
	if err != nil || len(vs) != 1 || vs[0].Active || vs[0].Status != "pass" {
		t.Fatalf("repaired Verify: %v %v", vs, err)
	}
	base, _ := os.ReadFile(calls)
	time.Sleep(11 * time.Second)
	after, _ := os.ReadFile(calls)
	delta := strings.TrimPrefix(string(after), string(base))
	if strings.Contains(delta, "retired.example.test") || !strings.Contains(delta, "retained.example.test") {
		t.Fatalf("post-repair SSH calls: %s", delta)
	}
	// A new state machine must also observe convergence and skip mutation.
	if err := decommission.NewExecutor([]*decommission.ExecStep{decommission.NewExecStep("repeat", p.ID(), steps[0].Action, step)}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	if applyCalls != 1 {
		t.Fatal("clean repeat re-executed apply")
	}
	rootCommand := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("sudo", append([]string{"-n"}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("root fixture: %v %s", err, out)
		}
	}
	expect := func(label string, repair, queryError bool) {
		t.Helper()
		t.Logf("query case: %s", label)
		// Reads may change atime, but cannot change bytes, ownership, mode or mtime.
		snapshot := func() string {
			var out []string
			for _, path := range []string{binary, config, unit, marker, state} {
				info, err := os.Lstat(path)
				if os.IsNotExist(err) {
					out = append(out, "missing")
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				entry := fmt.Sprintf("%s:%v:%d:%d", path, info.Mode(), info.ModTime().UnixNano(), info.Sys().(*syscall.Stat_t).Uid)
				if info.Mode().IsRegular() {
					raw, err := exec.Command("sudo", "-n", "sha256sum", path).Output()
					if err != nil {
						t.Fatal(err)
					}
					entry += string(raw)
				}
				out = append(out, entry)
			}
			return strings.Join(out, "\n")
		}
		before := snapshot()
		got, err := p.Inspect(ctx, input)
		after := snapshot()
		if before != after {
			t.Fatalf("%s query changed managed state", label)
		}
		if queryError {
			if err == nil {
				t.Fatalf("%s must fail explicitly, got %+v", label, got)
			}
			return
		}
		if err != nil || got.Found != repair {
			t.Fatalf("%s found=%v err=%v, want repair=%v", label, got.Found, err, repair)
		}
	}
	expect("proven active target-free runtime", false, false)
	setConfig(true)
	expect("listed target", true, false)
	setConfig(false)
	if err := os.Rename(config, config+".saved"); err != nil {
		t.Fatal(err)
	}
	expect("missing config but active daemon", true, false)
	if err := os.Rename(config+".saved", config); err != nil {
		t.Fatal(err)
	}
	rootCommand("rm", "--", marker)
	expect("missing marker", true, false)
	stamp()
	rootCommand("chmod", "0666", marker)
	expect("writable marker", true, false)
	stamp()
	rootCommand("chown", "65534", marker)
	expect("non-root owner", true, false)
	stamp()
	rootCommand("rm", "--", marker)
	if err := os.Symlink(binary, marker); err != nil {
		t.Fatal(err)
	}
	expect("symlink marker", true, false)
	rootCommand("rm", "--", marker)
	stamp()
	bad := write("bad-marker", "invalid proof\n")
	rootCommand("install", "-o", "root", "-g", "root", "-m", "0600", bad, marker)
	expect("malformed marker", true, false)
	stamp()
	oldUnit, _ := os.ReadFile(unit)
	write("probe.service", string(oldUnit)+"# interrupted unit update\n")
	expect("unit hash differs", true, false)
	write("probe.service", string(oldUnit))
	oldState, _ := os.ReadFile(state)
	setState(strings.Repeat("1", 32))
	expect("new invocation", true, false)
	write("service.json", string(oldState))
	write("race", "")
	expect("unstable invocation", true, false)
	if err := os.Remove(filepath.Join(dir, "race")); err != nil {
		t.Fatal(err)
	}
	write("show-error", "")
	expect("systemd unavailable", false, true)
	if err := os.Remove(filepath.Join(dir, "show-error")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(config, config+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(config, 0700); err != nil {
		t.Fatal(err)
	}
	expect("configuration cannot be read as a file", false, true)
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(config+".saved", config); err != nil {
		t.Fatal(err)
	}
	stop()
	setState("")
	expect("installed stopped enabled service", true, false)
	for _, path := range []string{binary, config, unit, marker} {
		if err := os.Rename(path, path+".saved"); err != nil {
			t.Fatal(err)
		}
	}
	// Captured from native systemd on an uninstalled unit; rc alone is not proof.
	write("service.json", `{"MainPID":"0","LoadState":"not-found","ActiveState":"inactive","SubState":"dead","UnitFileState":"","InvocationID":""}`)
	expect("never installed", false, false)
	setState("")
	expect("stopped enabled service with missing config", true, false)
}
