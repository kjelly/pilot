package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/availability"
	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/delivery"
	"github.com/kjelly/pilot/internal/store"
)

// fakeAllReachableProber reports every probed endpoint as reachable,
// regardless of whether its host name resolves to anything real. Tests that
// fake ansible/ansible-inventory binaries with placeholder host names (e.g.
// "host-a") use this so the availability gate added in deploy_availability.go
// does not depend on those names being genuinely dialable.
type fakeAllReachableProber struct{}

func (fakeAllReachableProber) Probe(_ context.Context, ep availability.Endpoint) availability.ProbeResult {
	return availability.ProbeResult{Host: ep.Host, Endpoint: ep.Addr, State: availability.ProbeReachable}
}

// stubDeploymentAvailabilityAllReachable overrides deployAvailabilityProber
// for the duration of a test so every candidate/support host is treated as
// reachable, restoring the real TCP prober on cleanup.
func stubDeploymentAvailabilityAllReachable(t *testing.T) {
	t.Helper()
	original := deployAvailabilityProber
	deployAvailabilityProber = fakeAllReachableProber{}
	t.Cleanup(func() { deployAvailabilityProber = original })
}

func TestEffectiveDeploymentLimit_UnchangedWhenNothingDeferred(t *testing.T) {
	candidates := []string{"a", "b", "c"}
	got := effectiveDeploymentLimit("playbooks/site.yml", "orig-limit", candidates, candidates, false)
	if got != "orig-limit" {
		t.Fatalf("effectiveDeploymentLimit() = %q, want unchanged %q", got, "orig-limit")
	}
	// Including the "caller passed no limit at all" case explicitly.
	if got := effectiveDeploymentLimit("playbooks/site.yml", "", candidates, candidates, false); got != "" {
		t.Fatalf("effectiveDeploymentLimit() = %q, want empty string preserved", got)
	}
}

func TestEffectiveDeploymentLimit_RewritesWhenHostsDeferred(t *testing.T) {
	candidates := []string{"vm-01", "vm-02", "vm-03"}
	included := []string{"vm-02"}
	got := effectiveDeploymentLimit("playbooks/site.yml", "orig-limit", candidates, included, false)
	want := "localhost,vm-02"
	if got != want {
		t.Fatalf("effectiveDeploymentLimit() = %q, want %q", got, want)
	}
	// A single-component playbook must not gain localhost.
	got = effectiveDeploymentLimit("playbooks/apply/docker-apply.yml", "orig-limit", candidates, included, false)
	if got != "vm-02" {
		t.Fatalf("effectiveDeploymentLimit() = %q, want %q", got, "vm-02")
	}
}

func TestEffectiveDeploymentLimit_RewritesWhenDependencyExpandedLimit(t *testing.T) {
	got := effectiveDeploymentLimit("playbooks/site.yml", "client-a", []string{"client-a", "server-a"}, []string{"client-a", "server-a"}, true)
	if want := "localhost,client-a,server-a"; got != want {
		t.Fatalf("effectiveDeploymentLimit() = %q, want %q", got, want)
	}
}

func TestRunPreflight_UsesResolvedAvailabilityLimit(t *testing.T) {
	binDir := t.TempDir()
	argsPath := filepath.Join(t.TempDir(), "preflight-args")
	t.Setenv("PILOT_PREFLIGHT_ARGS", argsPath)
	if err := os.WriteFile(filepath.Join(binDir, "ansible-playbook"), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PILOT_PREFLIGHT_ARGS\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	oldPrompt := activePromptAutomation
	activePromptAutomation = &promptAutomation{answers: []promptAnswer{{
		Prompt: "要先跑前置檢查", Select: "完整前置檢查",
	}}}
	t.Cleanup(func() { activePromptAutomation = oldPrompt })

	runner := ansible.NewRunner()
	ok, err := runPreflight(context.Background(), runner, &bytes.Buffer{}, "inventory.yml", "required-host")
	if err != nil || !ok {
		t.Fatalf("runPreflight() = ok:%v err:%v, want successful full preflight", ok, err)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(args, []byte("--limit\nrequired-host\n")) {
		t.Fatalf("preflight argv = %q, want resolved --limit excluding deferred optional hosts", args)
	}
}

func TestDeferredHostsMetadata(t *testing.T) {
	deferred := []delivery.DeferredHost{
		{Host: "vm-01", Reason: delivery.DeferredUnavailable},
		{Host: "vm-02", Reason: delivery.DeferredDependencyUnavailable, Dependency: "freeipa-server@ipa-1"},
	}
	got := deferredHostsMetadata(deferred)
	want := []string{"vm-01:unavailable", "vm-02:dependency_unavailable:freeipa-server@ipa-1"}
	if len(got) != len(want) {
		t.Fatalf("deferredHostsMetadata() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("deferredHostsMetadata()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if deferredHostsMetadata(nil) != nil {
		t.Fatalf("deferredHostsMetadata(nil) should stay nil so callers skip the metadata key entirely")
	}
}

func TestDeferredHostNames(t *testing.T) {
	deferred := []delivery.DeferredHost{
		{Host: "dt-dev", Reason: delivery.DeferredUnavailable},
		{Host: "dependency-host", Reason: delivery.DeferredDependencyUnavailable},
		{Host: "dt-dev", Reason: delivery.DeferredUnavailable},
		{Host: "", Reason: delivery.DeferredUnavailable},
	}
	got := deferredHostNames(deferred)
	want := []string{"dependency-host", "dt-dev"}
	if len(got) != len(want) {
		t.Fatalf("deferredHostNames() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("deferredHostNames()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if deferredHostNames(nil) != nil {
		t.Fatal("deferredHostNames(nil) should be nil")
	}
	extraVar, err := deferredHostsExtraVar(deferred)
	if err != nil {
		t.Fatalf("deferredHostsExtraVar() error = %v", err)
	}
	if extraVar != `pilot_deferred_hosts=["dependency-host","dt-dev"]` {
		t.Fatalf("deferredHostsExtraVar() = %q", extraVar)
	}
	emptyExtraVar, err := deferredHostsExtraVar(nil)
	if err != nil {
		t.Fatalf("deferredHostsExtraVar(nil) error = %v", err)
	}
	if emptyExtraVar != "pilot_deferred_hosts=[]" {
		t.Fatalf("deferredHostsExtraVar(nil) = %q", emptyExtraVar)
	}
}

func TestAvailabilityCandidateHostsIncludesFreeIPAIdentityDelegatees(t *testing.T) {
	groups := map[string][]string{
		"freeipa-client": {"dt-dev", "online-client"},
	}
	got := availabilityCandidateHosts([]string{"freeipa"}, []contract.Contract{{ID: "freeipa-identity"}}, groups)
	want := []string{"dt-dev", "freeipa", "online-client"}
	if len(got) != len(want) {
		t.Fatalf("availabilityCandidateHosts() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("availabilityCandidateHosts()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	got = availabilityCandidateHosts([]string{"freeipa"}, []contract.Contract{{ID: "freeipa-server"}}, groups)
	if len(got) != 1 || got[0] != "freeipa" {
		t.Fatalf("unrelated component candidates = %v, want [freeipa]", got)
	}
}

// fakeUnreachableProber reports every probed endpoint as transport-
// unreachable, so tests can exercise the block/defer paths deterministically
// without depending on real network timing (spec §9.5).
type fakeUnreachableProber struct{}

func (fakeUnreachableProber) Probe(_ context.Context, ep availability.Endpoint) availability.ProbeResult {
	return availability.ProbeResult{Host: ep.Host, Endpoint: ep.Addr, State: availability.ProbeUnreachable, Err: errors.New("test: simulated unreachable")}
}

func stubDeploymentAvailabilityAllUnreachable(t *testing.T) {
	t.Helper()
	original := deployAvailabilityProber
	deployAvailabilityProber = fakeUnreachableProber{}
	t.Cleanup(func() { deployAvailabilityProber = original })
}

// setUpAvailabilityFixture writes a fake ansible-inventory binary (reporting
// one "docker" host with the given deployment_availability hostvar, or no
// such key at all when policy is "") onto PATH, plus a minimal inventory.yml,
// and returns the resolved inventory path and the run history store's data
// dir. It intentionally does not fake the "ansible"/"ansible-playbook"
// binaries used by the actual apply path — the tests using this fixture
// expect executeRecordedDeployment to return before ever reaching that far.
func setUpAvailabilityFixture(t *testing.T, policy string) (inv, dataDir string) {
	t.Helper()
	root := repoRootForTest(t)
	t.Chdir(root)
	dataDir = t.TempDir()
	t.Setenv("PILOT_DATA_DIR", dataDir)
	binDir := t.TempDir()
	hostvars := `{}`
	if policy != "" {
		hostvars = `{"deployment_availability": "` + policy + `"}`
	}
	script := "#!/bin/sh\nprintf '%s\\n' '{\"_meta\": {\"hostvars\": {\"host-a\": " + hostvars + "}}, \"docker\": {\"hosts\": [\"host-a\"]}}'\n"
	if err := os.WriteFile(filepath.Join(binDir, "ansible-inventory"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	inv = filepath.Join(t.TempDir(), "inventory.yml")
	if err := os.WriteFile(inv, []byte("all:\n  hosts:\n    host-a: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return inv, dataDir
}

func TestExecuteRecordedDeployment_RequiredHostUnavailableBlocksBeforeMutation(t *testing.T) {
	inv, dataDir := setUpAvailabilityFixture(t, "") // no policy set -> effective required
	stubDeploymentAvailabilityAllUnreachable(t)

	runner := ansible.NewRunner()
	runner.Timeout = 5 * time.Second
	err := executeRecordedDeployment(context.Background(), runner, &bytes.Buffer{}, "playbooks/apply/docker-apply.yml", inv, "", "", []string{"stage=sandbox"}, vaultInput{}, "sandbox", []string{"docker"})
	if err == nil {
		t.Fatal("executeRecordedDeployment() error = nil, want a blocking error for an unreachable required host")
	}

	s, openErr := store.Open(filepath.Join(dataDir, "history.db"))
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer s.Close()
	runs, listErr := s.ListRuns(store.RunFilter{})
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(runs) != 0 {
		t.Fatalf("runs = %+v, want none recorded — a blocked deployment must not start an evidence run or invoke apply", runs)
	}
}

// TestExecuteRecordedDeployment_InvalidPolicyBlocksEvenWhenReachable guards
// spec §7.6/§12.1: an unrecognized deployment_availability value must fail
// validation before mutation regardless of reachability. Before this test
// was added, a reachable host with a garbage policy value silently fell
// through ResolveExecutionScope's `case c.Reachable` branch as if it were
// valid.
func TestExecuteRecordedDeployment_InvalidPolicyBlocksEvenWhenReachable(t *testing.T) {
	inv, dataDir := setUpAvailabilityFixture(t, "sometimes") // not "", "required", or "optional"
	stubDeploymentAvailabilityAllReachable(t)

	runner := ansible.NewRunner()
	runner.Timeout = 5 * time.Second
	err := executeRecordedDeployment(context.Background(), runner, &bytes.Buffer{}, "playbooks/apply/docker-apply.yml", inv, "", "", []string{"stage=sandbox"}, vaultInput{}, "sandbox", []string{"docker"})
	if err == nil {
		t.Fatal("executeRecordedDeployment() error = nil, want a blocking error for an invalid deployment_availability value even though the host is reachable")
	}

	s, openErr := store.Open(filepath.Join(dataDir, "history.db"))
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer s.Close()
	runs, listErr := s.ListRuns(store.RunFilter{})
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(runs) != 0 {
		t.Fatalf("runs = %+v, want none recorded — an invalid policy must block before any evidence run or apply", runs)
	}
}

func TestExecuteRecordedDeployment_AllOptionalUnavailableIsNoOp(t *testing.T) {
	inv, dataDir := setUpAvailabilityFixture(t, "optional")
	stubDeploymentAvailabilityAllUnreachable(t)

	runner := ansible.NewRunner()
	runner.Timeout = 5 * time.Second
	err := executeRecordedDeployment(context.Background(), runner, &bytes.Buffer{}, "playbooks/apply/docker-apply.yml", inv, "", "", []string{"stage=sandbox"}, vaultInput{}, "sandbox", []string{"docker"})
	if err != nil {
		t.Fatalf("executeRecordedDeployment() error = %v, want nil (successful no-op when every candidate host is optional and unavailable)", err)
	}

	s, openErr := store.Open(filepath.Join(dataDir, "history.db"))
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer s.Close()
	runs, listErr := s.ListRuns(store.RunFilter{})
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(runs) != 0 {
		t.Fatalf("runs = %+v, want none recorded — a no-op deployment must not invoke apply", runs)
	}
}
