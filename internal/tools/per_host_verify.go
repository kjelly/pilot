package tools

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/anomalyco/pilot/internal/spec"
)

// ansibleJSONInvocation is the controller-level result of one isolated
// ansible ad-hoc process. The callback payload, rather than ExitCode, is the
// authority for the remote host result: Ansible returns 2 for a module error
// even when the module's own rc contains the useful evidence.
type ansibleJSONInvocation struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

type ansibleHostLister func(context.Context, string, string) ([]string, error)
type ansibleJSONRunner func(context.Context, []string, int) ansibleJSONInvocation

const defaultPerHostWorkers = 8

// resolveRemoteHosts converts all user-facing host selectors through Ansible
// itself. It deliberately does not parse inventory YAML or Ansible host
// patterns in Go: Ansible's --list-hosts remains the single source of truth.
func (t *VerifySpecTool) resolveRemoteHosts(ctx context.Context, parsed *spec.Spec, host string) (expectedHostResolution, error) {
	list := t.listHosts
	if list == nil {
		list = t.listAnsibleHosts
	}
	inventoryHosts, err := list(ctx, "all", "")
	if err != nil {
		return expectedHostResolution{}, fmt.Errorf("resolve inventory hosts: %w", err)
	}
	selections := make([]hostSelection, 0, 2)
	if host != "" {
		hosts, err := list(ctx, host, "")
		if err != nil {
			return expectedHostResolution{}, fmt.Errorf("resolve --host %q: %w", host, err)
		}
		selections = append(selections, hostSelection{Name: "--host", Provided: true, Hosts: hosts})
	}
	if t.Limit != "" {
		hosts, err := list(ctx, "all", t.Limit)
		if err != nil {
			return expectedHostResolution{}, fmt.Errorf("resolve --limit %q: %w", t.Limit, err)
		}
		selections = append(selections, hostSelection{Name: "--limit", Provided: true, Hosts: hosts})
	}

	specHosts := make([]string, 0, len(parsed.Hosts))
	for _, target := range parsed.Hosts {
		specHosts = append(specHosts, target.Hostname)
	}
	resolution, err := resolveExpectedHosts(expectedHostInput{
		InventoryHosts:      inventoryHosts,
		ExecutionSelections: selections,
		SpecTargetsDeclared: parsed.HasTargets(),
		SpecTargetHosts:     specHosts,
	})
	if err != nil {
		return expectedHostResolution{}, err
	}
	return resolution, nil
}

// listAnsibleHosts asks Ansible to resolve a host pattern against the exact
// inventory that will execute verification. list-hosts emits a stable,
// human-readable inventory subset; parseAnsibleListHosts accepts only that
// shape and fails closed on anything ambiguous.
func (t *VerifySpecTool) listAnsibleHosts(ctx context.Context, pattern, limit string) ([]string, error) {
	args := []string{pattern, "-i", t.Inventory, "--list-hosts"}
	if limit != "" {
		args = append(args, "-l", limit)
	}
	out, err := exec.CommandContext(ctx, "ansible", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ansible --list-hosts: %w: %s", err, strings.TrimSpace(string(out)))
	}
	hosts, err := parseAnsibleListHosts(string(out))
	if err != nil {
		return nil, err
	}
	return hosts, nil
}

func parseAnsibleListHosts(raw string) ([]string, error) {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	found := false
	var hosts []string
	for scanner.Scan() {
		line := scanner.Text()
		if !found {
			if strings.Contains(line, "hosts (") && strings.Contains(line, "):") {
				found = true
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if len(line) == len(strings.TrimLeft(line, " \t")) {
			break
		}
		host := strings.Fields(line)
		if len(host) != 1 {
			return nil, fmt.Errorf("ansible --list-hosts: malformed host line %q", line)
		}
		hosts = append(hosts, host[0])
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("ansible --list-hosts: read output: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("ansible --list-hosts: no host-list header in output %q", strings.TrimSpace(raw))
	}
	sort.Strings(hosts)
	return hosts, nil
}

// runAnsiblePerHost invokes a row separately for every resolved host. No
// failed host cancels its siblings; output order is deterministic by host.
func (t *VerifySpecTool) runAnsiblePerHost(ctx context.Context, row spec.Row, hosts []string, timeoutSec int) []VerifyRow {
	probes := runBoundedPerHost(ctx, hosts, t.perHostWorkers(), func(ctx context.Context, host string) callbackProbeResult {
		return t.invokeAnsibleJSON(ctx, host, row, timeoutSec)
	})
	rows := make([]VerifyRow, 0, len(probes))
	for _, probe := range probes {
		vr := VerifyRow{
			ID:          row.ID,
			Host:        probe.Host,
			ExitCode:    probe.ExitCode,
			ProbeStatus: string(probe.Status),
			Stdout:      probe.Stdout,
			Stderr:      probe.Stderr,
			Message:     probe.Message,
		}
		if probe.Status != callbackStatusOK {
			vr.Status = "fail"
			vr.Detail = callbackFailureDetail(probe)
			rows = append(rows, vr)
			continue
		}
		detail := fmt.Sprintf("(rc=%d) %s", probe.ExitCode, probe.Stdout)
		ok, mismatch := evaluateV1Expected(row.Expected, detail, probe.ExitCode)
		vr.Detail = mismatch
		vr.Status = "pass"
		if !ok {
			vr.Status = "fail"
		}
		rows = append(rows, vr)
	}
	return rows
}

func callbackFailureDetail(probe callbackProbeResult) string {
	parts := []string{fmt.Sprintf("probe_status=%s", probe.Status), fmt.Sprintf("rc=%d", probe.ExitCode)}
	if probe.Message != "" {
		parts = append(parts, probe.Message)
	} else if probe.Stderr != "" {
		parts = append(parts, probe.Stderr)
	}
	return strings.Join(parts, ": ")
}

func (t *VerifySpecTool) perHostWorkers() int {
	if t.PerHostWorkers > 0 && t.PerHostWorkers <= defaultPerHostWorkers {
		return t.PerHostWorkers
	}
	return defaultPerHostWorkers
}

func (t *VerifySpecTool) invokeAnsibleJSON(ctx context.Context, host string, row spec.Row, timeoutSec int) callbackProbeResult {
	if err := ctx.Err(); err != nil {
		return callbackProbeResult{Host: host, ExitCode: -1, Status: callbackStatusRunnerError, Message: "parent_cancelled: " + err.Error()}
	}
	module := adHocModule(row.Command)
	args := []string{host, "-i", t.Inventory, "-m", module, "-a", row.Command}
	if spec.NeedsBecome(row) {
		args = append(args, "-b")
	}
	run := t.runJSON
	if run == nil {
		run = t.execAnsibleJSON
	}
	result := run(ctx, args, timeoutSec)
	if ctx.Err() != nil {
		return callbackProbeResult{Host: host, ExitCode: -1, Status: callbackStatusRunnerError, Message: "parent_cancelled: " + ctx.Err().Error()}
	}
	if result.Err != nil && errors.Is(result.Err, context.DeadlineExceeded) {
		return callbackProbeResult{Host: host, ExitCode: -1, Status: callbackStatusTimeout, Message: "per-host invocation timed out"}
	}
	probes, err := decodeAnsibleCallbackSpike([]byte(result.Stdout), []string{host})
	if err != nil {
		message := fmt.Sprintf("callback decode: %v", err)
		if result.Err != nil {
			message += "; invocation: " + result.Err.Error()
		}
		if result.Stderr != "" {
			message += "; stderr: " + normalizeCallbackText(result.Stderr)
		}
		return callbackProbeResult{Host: host, ExitCode: -1, Status: callbackStatusRunnerError, Message: message}
	}
	return probes[0]
}

func (t *VerifySpecTool) execAnsibleJSON(ctx context.Context, args []string, timeoutSec int) ansibleJSONInvocation {
	cctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "ansible", args...)
	cmd.Env = append(os.Environ(), "ANSIBLE_LOAD_CALLBACK_PLUGINS=1", "ANSIBLE_STDOUT_CALLBACK=ansible.posix.json")
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	rc := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		rc = exitErr.ExitCode()
	}
	if cctx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
		err = context.DeadlineExceeded
	}
	return ansibleJSONInvocation{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: rc, Err: err}
}

// runBoundedPerHost supplies the isolation and cancellation semantics shared
// by every verification row. Pending work becomes runner_error on parent
// cancellation; work already started receives the context and reports its own
// result. Each host appears exactly once in the returned sorted slice.
func runBoundedPerHost(ctx context.Context, hosts []string, workers int, invoke func(context.Context, string) callbackProbeResult) []callbackProbeResult {
	unique := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		if host != "" {
			unique[host] = struct{}{}
		}
	}
	hosts = make([]string, 0, len(unique))
	for host := range unique {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	if workers < 1 {
		workers = 1
	}
	if workers > defaultPerHostWorkers {
		workers = defaultPerHostWorkers
	}
	results := make(map[string]callbackProbeResult, len(hosts))
	jobs := make(chan string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				result := invoke(ctx, host)
				mu.Lock()
				results[host] = result
				mu.Unlock()
			}
		}()
	}
dispatch:
	for _, host := range hosts {
		if ctx.Err() != nil {
			break
		}
		select {
		case jobs <- host:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	wg.Wait()
	for _, host := range hosts {
		if _, ok := results[host]; !ok {
			results[host] = callbackProbeResult{Host: host, ExitCode: -1, Status: callbackStatusRunnerError, Message: "parent_cancelled: " + ctx.Err().Error()}
		}
	}
	out := make([]callbackProbeResult, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, results[host])
	}
	return out
}
