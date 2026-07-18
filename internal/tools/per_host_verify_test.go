package tools

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anomalyco/pilot/internal/spec"
)

func TestParseAnsibleListHosts(t *testing.T) {
	hosts, err := parseAnsibleListHosts("playbook: all\n\n  hosts (2):\n    beta\n    alpha\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(hosts, ","); got != "alpha,beta" {
		t.Fatalf("hosts=%q", got)
	}
	if _, err := parseAnsibleListHosts("not an ansible host list"); err == nil {
		t.Fatal("expected malformed output to fail closed")
	}
}

func TestVerifySpec_RemotePerHostCallback(t *testing.T) {
	tmp := t.TempDir()
	specPath := filepath.Join(tmp, "remote.md")
	body := `# Verification Spec — remote

## 1. Targets

| Hostname | Group |
|----------|-------|
| host-a | test |
| host-b | test |

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | test | callback succeeds | ~ready | ` + "`echo ready`" + ` |
| C2 | test | callback fails | present | ` + "`false`" + ` |
`
	if err := writeFile(specPath, body); err != nil {
		t.Fatal(err)
	}

	tool := &VerifySpecTool{
		Inventory:      "inventory.yml",
		PerHostWorkers: 2,
		listHosts: func(_ context.Context, pattern, limit string) ([]string, error) {
			if limit != "" {
				return nil, errors.New("unexpected limit")
			}
			switch pattern {
			case "all":
				return []string{"host-b", "host-a"}, nil
			default:
				return nil, errors.New("unexpected pattern " + pattern)
			}
		},
		runJSON: func(_ context.Context, args []string, _ int) ansibleJSONInvocation {
			host := args[0]
			command := args[6]
			if command == "false" {
				return ansibleJSONInvocation{Stdout: `{"plays":[{"tasks":[{"hosts":{"` + host + `":{"failed":true,"msg":"failed","rc":9}}}]}]}`, ExitCode: 2}
			}
			return ansibleJSONInvocation{Stdout: `{"plays":[{"tasks":[{"hosts":{"` + host + `":{"stdout":"ready","rc":0}}}]}]}`}
		},
	}
	res, err := tool.Execute(context.Background(), mustJSON(t, map[string]any{"spec_path": specPath}))
	if err != nil || res.IsError {
		t.Fatalf("Execute err=%v result=%+v", err, res)
	}
	rows, err := ReadNDJSON(res.Content)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("rows=%d want 4: %s", len(rows), res.Content)
	}
	for _, row := range rows[:2] {
		if row.ID != "C1" || row.Status != "pass" || row.ProbeStatus != "ok" {
			t.Errorf("C1 row=%+v", row)
		}
	}
	for _, row := range rows[2:] {
		if row.ID != "C2" || row.Status != "fail" || row.ProbeStatus != "module_error" || row.ExitCode != 9 {
			t.Errorf("C2 row=%+v", row)
		}
	}
}

func TestVerifySpec_RemoteScopeRequiresTargetsOrSelector(t *testing.T) {
	tmp := t.TempDir()
	specPath := filepath.Join(tmp, "scope.md")
	if err := writeFile(specPath, `# Verification Spec — scope

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | test | scope | present | `+"`true`"+` |
`); err != nil {
		t.Fatal(err)
	}
	tool := &VerifySpecTool{
		Inventory: "inventory.yml",
		listHosts: func(_ context.Context, pattern, _ string) ([]string, error) {
			if pattern != "all" {
				t.Fatalf("pattern=%q", pattern)
			}
			return []string{"host-a"}, nil
		},
	}
	res, err := tool.Execute(context.Background(), mustJSON(t, map[string]any{"spec_path": specPath}))
	if err != nil || !res.IsError || !strings.Contains(res.Content, "explicit --host/--limit") {
		t.Fatalf("err=%v result=%+v", err, res)
	}
}

func TestRunBoundedPerHost_DoesNotShortCircuitAndCapsWorkers(t *testing.T) {
	hosts := []string{"h3", "h1", "h2"}
	var mu sync.Mutex
	started := make([]string, 0, len(hosts))
	results := runBoundedPerHost(context.Background(), hosts, 99, func(_ context.Context, host string) callbackProbeResult {
		mu.Lock()
		started = append(started, host)
		mu.Unlock()
		status := callbackStatusOK
		if host == "h1" {
			status = callbackStatusModuleError
		}
		return callbackProbeResult{Host: host, Status: status}
	})
	if len(started) != 3 || len(results) != 3 {
		t.Fatalf("started=%v results=%v", started, results)
	}
	if results[0].Host != "h1" || results[1].Host != "h2" || results[2].Host != "h3" {
		t.Fatalf("result order=%v", results)
	}
	if results[0].Status != callbackStatusModuleError || results[1].Status != callbackStatusOK {
		t.Fatalf("results=%+v", results)
	}
}

func TestRunBoundedPerHost_DeduplicatesHosts(t *testing.T) {
	var calls atomic.Int32
	results := runBoundedPerHost(context.Background(), []string{"b", "a", "a"}, 1, func(_ context.Context, host string) callbackProbeResult {
		calls.Add(1)
		return callbackProbeResult{Host: host, Status: callbackStatusOK}
	})
	if calls.Load() != 2 || len(results) != 2 || results[0].Host != "a" || results[1].Host != "b" {
		t.Fatalf("calls=%d results=%+v", calls.Load(), results)
	}
}

func TestRunBoundedPerHost_CapsConcurrencyAtEight(t *testing.T) {
	hosts := []string{"h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8", "h9"}
	started := make(chan struct{}, len(hosts))
	release := make(chan struct{})
	var active, maximum atomic.Int32
	done := make(chan []callbackProbeResult, 1)
	go func() {
		done <- runBoundedPerHost(context.Background(), hosts, 99, func(_ context.Context, host string) callbackProbeResult {
			current := active.Add(1)
			for {
				seen := maximum.Load()
				if current <= seen || maximum.CompareAndSwap(seen, current) {
					break
				}
			}
			started <- struct{}{}
			<-release
			active.Add(-1)
			return callbackProbeResult{Host: host, Status: callbackStatusOK}
		})
	}()
	for i := 0; i < defaultPerHostWorkers; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("only %d workers started", i)
		}
	}
	if got := maximum.Load(); got != defaultPerHostWorkers {
		t.Fatalf("maximum concurrent invocations=%d, want %d", got, defaultPerHostWorkers)
	}
	close(release)
	select {
	case results := <-done:
		if len(results) != len(hosts) {
			t.Fatalf("results=%d want=%d", len(results), len(hosts))
		}
	case <-time.After(time.Second):
		t.Fatal("runner did not complete")
	}
}

func TestInvokeAnsibleJSON_DeadlineIsHostTimeout(t *testing.T) {
	tool := &VerifySpecTool{
		Inventory: "inventory.yml",
		runJSON: func(_ context.Context, _ []string, _ int) ansibleJSONInvocation {
			return ansibleJSONInvocation{Err: context.DeadlineExceeded}
		},
	}
	result := tool.invokeAnsibleJSON(context.Background(), "host-a", spec.Row{Command: "true"}, 1)
	if result.Status != callbackStatusTimeout || result.Host != "host-a" {
		t.Fatalf("result=%+v", result)
	}
}

func TestRunBoundedPerHost_ParentCancellationMarksPending(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	allowFinish := make(chan struct{})
	done := make(chan []callbackProbeResult, 1)
	go func() {
		done <- runBoundedPerHost(ctx, []string{"a", "b"}, 1, func(_ context.Context, host string) callbackProbeResult {
			if host == "a" {
				close(started)
				<-allowFinish
			}
			return callbackProbeResult{Host: host, Status: callbackStatusOK}
		})
	}()
	<-started
	cancel()
	close(allowFinish)
	select {
	case results := <-done:
		if results[1].Host != "b" || results[1].Status != callbackStatusRunnerError || !strings.Contains(results[1].Message, "parent_cancelled") {
			t.Fatalf("pending result=%+v", results[1])
		}
	case <-time.After(time.Second):
		t.Fatal("runner did not return after parent cancellation")
	}
}
