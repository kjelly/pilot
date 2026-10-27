package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/availability"
	"github.com/kjelly/pilot/internal/contract"
)

func TestReconcileRejectsFlagMisuse(t *testing.T) {
	prevForce, prevPreview, prevActions, prevComponents, prevStage, prevHours := reconcileForceFlag, reconcilePreviewOnlyFlag, reconcileActionsPath, reconcileComponentFlags, stageFlag, stagingAttestedHoursFlag
	t.Cleanup(func() {
		reconcileForceFlag, reconcilePreviewOnlyFlag, reconcileActionsPath, reconcileComponentFlags, stageFlag, stagingAttestedHoursFlag = prevForce, prevPreview, prevActions, prevComponents, prevStage, prevHours
	})
	scenario := filepath.Join(t.TempDir(), "scenario.json")
	for _, tt := range []struct {
		name           string
		force, preview bool
		actions        string
		components     []string
		stage, hours   string
		wantErr        string
	}{
		{name: "force and preview-only", force: true, preview: true, components: []string{"freeipa-identity"}, wantErr: "--force 不能與 --preview-only"},
		{name: "actions with component", actions: scenario, components: []string{"freeipa-identity"}, wantErr: "--actions 不能與"},
		{name: "actions with stage", actions: scenario, stage: "staging", wantErr: "--actions 不能與"},
		{name: "preview-only without component", preview: true, wantErr: "需要用 --component"},
		{name: "force without component", force: true, wantErr: "需要用 --component"},
		{name: "prod without attestation", preview: true, components: []string{"freeipa-identity"}, stage: "prod", wantErr: "--staging-attested-within-hours"},
	} {
		reconcileForceFlag, reconcilePreviewOnlyFlag, reconcileActionsPath = tt.force, tt.preview, tt.actions
		reconcileComponentFlags, stageFlag, stagingAttestedHoursFlag = tt.components, tt.stage, tt.hours
		if err := runReconcile(&cobra.Command{}, nil); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("%s: error = %v, want %q", tt.name, err, tt.wantErr)
		}
	}
}

// TestReconcileNonInteractiveRunsWithoutTTY mirrors the deploy test: both
// non-interactive modes install their driver before the TTY gate.
func TestReconcileNonInteractiveRunsWithoutTTY(t *testing.T) {
	prevTTY, prevForce, prevPreview, prevTimeout, prevPrompt := reconcileStdinIsTerminal, reconcileForceFlag, reconcilePreviewOnlyFlag, reconcileTimeoutFlag, activePromptAutomation
	t.Cleanup(func() {
		reconcileStdinIsTerminal, reconcileForceFlag, reconcilePreviewOnlyFlag, reconcileTimeoutFlag, activePromptAutomation = prevTTY, prevForce, prevPreview, prevTimeout, prevPrompt
	})
	reconcileStdinIsTerminal = func() bool { return false }
	activePromptAutomation = nil
	// --timeout is parsed right after the TTY gate.
	reconcileTimeoutFlag = "not-a-duration"

	reconcileForceFlag, reconcilePreviewOnlyFlag = false, false
	if err := runReconcileInteractive(&cobra.Command{}); err == nil || !strings.Contains(err.Error(), "--preview-only") {
		t.Fatalf("plain reconcile without a TTY: error = %v, want the TTY error naming --preview-only", err)
	}
	for _, mode := range []struct{ force, preview bool }{{force: true}, {preview: true}} {
		reconcileForceFlag, reconcilePreviewOnlyFlag = mode.force, mode.preview
		err := runReconcileInteractive(&cobra.Command{})
		if err == nil || strings.Contains(err.Error(), "TTY") || !strings.Contains(err.Error(), "--timeout") {
			t.Fatalf("force=%v preview-only=%v without a TTY: error = %v, want to pass the TTY gate and stop at --timeout", mode.force, mode.preview, err)
		}
		if activePromptAutomation != nil {
			t.Fatal("the automation driver outlived runReconcileInteractive")
		}
	}
}

func TestReconcileComponentIndexes(t *testing.T) {
	entries := []deployPlaybook{{Key: "freeipa-identity"}, {Key: "freeipa-dns-client"}, {Key: "pilot-gateway-scope"}}
	got, err := reconcileComponentIndexes(entries, []string{"pilot-gateway-scope", "freeipa-identity", "pilot-gateway-scope"})
	if err != nil || !reflect.DeepEqual(got, []int{0, 2}) {
		t.Fatalf("reconcileComponentIndexes() = %v, %v; want [0 2] in menu order", got, err)
	}
	_, err = reconcileComponentIndexes(entries, []string{"freeipa-identity", "freeipa-server"})
	if err == nil || !strings.Contains(err.Error(), `"freeipa-server"`) || !strings.Contains(err.Error(), "freeipa-dns-client") {
		t.Fatalf("unknown key: error = %v, want it named along with the available keys", err)
	}
}

// fakeDownHostsProber reports the named hosts unreachable and every other
// host reachable.
type fakeDownHostsProber map[string]bool

func (down fakeDownHostsProber) Probe(_ context.Context, ep availability.Endpoint) availability.ProbeResult {
	if down[ep.Host] {
		return availability.ProbeResult{Host: ep.Host, Endpoint: ep.Addr, State: availability.ProbeUnreachable, Err: errors.New("test: simulated unreachable")}
	}
	return availability.ProbeResult{Host: ep.Host, Endpoint: ep.Addr, State: availability.ProbeReachable}
}

// TestExecuteCatalogReconcileBatch_PreviewOnly runs the real reconcile batch
// (two requests, each with a sameHosts dependency) under the --preview-only
// driver: every playbook in the plan is previewed and none is applied, a
// failing preview stops the plan, and availability deferrals are reported as
// what they are instead of as passed previews.
func TestExecuteCatalogReconcileBatch_PreviewOnly(t *testing.T) {
	withDependency := []string{"leaf-apply.yml", "consumer-apply.yml", "leaf-apply.yml", "consumer-apply.yml"}
	for _, tt := range []struct {
		name        string
		component   string            // each of the two requests reconciles this component
		hostvars    map[string]string // host -> deployment_availability ("" = unset)
		down        []string
		previewExit string
		wantRuns    []string // playbooks previewed, in order
		wantErr     string   // "" = success; "preview failure" = a failed preview
		wantOut     []string
		wantNotOut  []string
	}{
		{
			name: "previews pass", component: "consumer", hostvars: map[string]string{"host-a": ""}, previewExit: "0", wantRuns: withDependency,
			wantOut: []string{"4 支 playbook 的預覽都通過"},
		},
		{
			name: "first preview fails", component: "consumer", hostvars: map[string]string{"host-a": ""}, previewExit: "2", wantRuns: withDependency[:1],
			wantErr: "preview failure", wantNotOut: []string{"預覽都通過"},
		},
		{
			// Every target is an unreachable optional host: availability turns
			// each playbook into a no-op, so nothing was previewed.
			name: "every host deferred", component: "consumer", hostvars: map[string]string{"host-a": "optional"}, down: []string{"host-a"}, previewExit: "0", wantRuns: nil,
			wantErr: "4 支 playbook 的目標主機全部無法連線而延後，沒有預覽", wantNotOut: []string{"預覽都通過"},
		},
		{
			// host-b is deferred, host-a is previewed: a pass that names host-b.
			// leaf (one-or-more, no dependency) can span both hosts.
			name: "some hosts deferred", component: "leaf", hostvars: map[string]string{"host-a": "", "host-b": "optional"}, down: []string{"host-b"}, previewExit: "0",
			wantRuns: []string{"leaf-apply.yml", "leaf-apply.yml"},
			wantOut:  []string{"leaf-apply.yml 已預覽，但 optional 主機 host-b 無法連線而延後", "2 支 playbook 的預覽都通過"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := writeSameHostsCascadeFixture(t)
			t.Chdir(root)
			dataDir = t.TempDir()
			t.Cleanup(func() { dataDir = "" })

			var hosts []string
			for host := range tt.hostvars {
				hosts = append(hosts, host)
			}
			sort.Strings(hosts)
			var hostvars, quoted, listed []string
			invYAML := "all:\n  hosts:\n"
			for _, host := range hosts {
				vars := "{}"
				if policy := tt.hostvars[host]; policy != "" {
					vars = `{"deployment_availability":"` + policy + `"}`
				}
				hostvars = append(hostvars, `"`+host+`":`+vars)
				quoted = append(quoted, `"`+host+`"`)
				listed = append(listed, "'    "+host+"'")
				invYAML += "    " + host + ": {}\n"
			}
			group := `{"hosts":[` + strings.Join(quoted, ",") + `]}`
			invJSON := `{"_meta":{"hostvars":{` + strings.Join(hostvars, ",") + `}},"leaf":` + group + `,"consumer":` + group + `}`

			binDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(binDir, "ansible-inventory"), []byte("#!/bin/sh\nprintf '%s\\n' '"+invJSON+"'\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			ansibleFixture := "#!/bin/sh\ncase \"$*\" in\n" +
				"  *--list-hosts*) printf '%s\\n' '  hosts (" + strconv.Itoa(len(hosts)) + "):' " + strings.Join(listed, " ") + "; exit 0 ;;\n" +
				"  *) printf '{\"plays\":[{\"tasks\":[{\"hosts\":{\"host-a\":{\"stdout\":\"unknown\",\"rc\":0}}}]}]}\\n' ;;\nesac\n"
			if err := os.WriteFile(filepath.Join(binDir, "ansible"), []byte(ansibleFixture), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

			inv := filepath.Join(t.TempDir(), "inventory.yml")
			if err := os.WriteFile(inv, []byte(invYAML), 0o600); err != nil {
				t.Fatal(err)
			}
			argsPath := filepath.Join(t.TempDir(), "ansible-playbook-args")
			playbook := filepath.Join(t.TempDir(), "ansible-playbook")
			script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + argsPath + "\n" + fakePlayRecapScript +
				"case \"$1\" in --check) exit " + tt.previewExit + " ;; esac\n"
			if err := os.WriteFile(playbook, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			runner := ansible.NewRunner()
			runner.Binary = playbook
			runner.Timeout = 5 * time.Second

			oldPrompt := activePromptAutomation
			activePromptAutomation = &promptAutomation{useDefaults: true, previewOnly: true}
			t.Cleanup(func() { activePromptAutomation = oldPrompt })
			down := fakeDownHostsProber{}
			for _, host := range tt.down {
				down[host] = true
			}
			oldProber := deployAvailabilityProber
			deployAvailabilityProber = down
			t.Cleanup(func() { deployAvailabilityProber = oldProber })

			var out bytes.Buffer
			request := catalogDeploymentRequest{
				playbook:       tt.component + "-apply.yml",
				inv:            inv,
				extraVars:      []string{"stage=sandbox"},
				stage:          "sandbox",
				componentHints: []string{tt.component},
			}
			err := executeCatalogReconcileBatch(context.Background(), runner, &out, []catalogDeploymentRequest{request, request})
			switch tt.wantErr {
			case "":
				if err != nil {
					t.Fatalf("executeCatalogReconcileBatch() error = %v\n%s", err, out.String())
				}
			case "preview failure":
				if err == nil || errors.Is(err, errPreviewOnlyStop) || errors.Is(err, errDeployAborted) {
					t.Fatalf("executeCatalogReconcileBatch() error = %v, want the preview failure", err)
				}
			default:
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("executeCatalogReconcileBatch() error = %v, want %q\n%s", err, tt.wantErr, out.String())
				}
			}

			data, readErr := os.ReadFile(argsPath)
			if readErr != nil && !os.IsNotExist(readErr) {
				t.Fatal(readErr)
			}
			// The defaults choose the full preflight, which runs before each preview.
			var runs []string
			for _, run := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				if run != "" && !strings.HasPrefix(run, "playbooks/preflight.yml ") {
					runs = append(runs, run)
				}
			}
			if len(runs) != len(tt.wantRuns) {
				t.Fatalf("ansible-playbook runs = %q, want previews of %q\n%s", runs, tt.wantRuns, out.String())
			}
			for i, run := range runs {
				if !strings.HasPrefix(run, "--check --diff ") || !strings.Contains(run, tt.wantRuns[i]) {
					t.Fatalf("run %d = %q, want a --check --diff preview of %s and no apply", i, run, tt.wantRuns[i])
				}
				limit := strings.Fields(strings.SplitN(run, "--limit ", 2)[1])[0]
				for _, host := range tt.down {
					if slices.Contains(strings.Split(limit, ","), host) {
						t.Fatalf("run %d = %q previews deferred host %s", i, run, host)
					}
				}
			}
			for _, want := range tt.wantOut {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("output lacks %q:\n%s", want, out.String())
				}
			}
			for _, notWant := range tt.wantNotOut {
				if strings.Contains(out.String(), notWant) {
					t.Fatalf("output claims %q:\n%s", notWant, out.String())
				}
			}
		})
	}
}

// TestPreviewOnlySummary pins the summary contract: deferred hosts of a
// previewed playbook are named, and a playbook that never previewed, or one
// that left no record at all, fails the plan.
func TestPreviewOnlySummary(t *testing.T) {
	var out bytes.Buffer
	previewed := []previewOnlyRecord{
		{Playbook: "leaf-apply.yml", Previewed: true},
		{Playbook: "consumer-apply.yml", Previewed: true, Deferred: []string{"host-b"}},
	}
	err := previewOnlySummary(&out, previewed, 2)
	if err != nil || !strings.Contains(out.String(), "consumer-apply.yml 已預覽，但 optional 主機 host-b") || !strings.Contains(out.String(), "2 支 playbook 的預覽都通過") {
		t.Fatalf("all previewed: error = %v, output %q", err, out.String())
	}

	out.Reset()
	err = previewOnlySummary(&out, []previewOnlyRecord{
		{Playbook: "leaf-apply.yml", Previewed: true},
		{Playbook: "consumer-apply.yml", Deferred: []string{"host-a"}},
	}, 2)
	if err == nil || !strings.Contains(err.Error(), "consumer-apply.yml(延後：host-a)") || strings.Contains(out.String(), "預覽都通過") {
		t.Fatalf("one never previewed: error = %v, output %q", err, out.String())
	}

	out.Reset()
	if err := previewOnlySummary(&out, previewed, 3); err == nil || !strings.Contains(err.Error(), "計畫有 3 支 playbook，但只有 2 支") || strings.Contains(out.String(), "預覽都通過") {
		t.Fatalf("a planned playbook left no record: error = %v, output %q", err, out.String())
	}

	if err := previewOnlySummary(&bytes.Buffer{}, nil, 0); err == nil {
		t.Fatal("no records: error = nil, want a failure")
	}
}

func TestReconcileExit(t *testing.T) {
	failure := errors.New("preview failed")
	for _, tt := range []struct {
		name        string
		err         error
		previewOnly bool
		wantErr     string
	}{
		{name: "interactive cancel is clean", err: errDeployAborted},
		{name: "preview-only abort fails", err: errDeployAborted, previewOnly: true, wantErr: "在預覽完成之前就停止了"},
		{name: "preview-only success", previewOnly: true},
		{name: "failures pass through", err: failure, previewOnly: true, wantErr: "preview failed"},
	} {
		err := reconcileExit(tt.err, tt.previewOnly)
		if (tt.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tt.wantErr)) {
			t.Errorf("%s: reconcileExit() = %v, want %q", tt.name, err, tt.wantErr)
		}
	}
}

// writeReconcileBatchFixture fakes ansible-inventory/ansible for the
// leaf/consumer cascade fixture with the given hosts in both groups, and
// returns the inventory path.
func writeReconcileBatchFixture(t *testing.T, hostvars map[string]string) string {
	t.Helper()
	root := writeSameHostsCascadeFixture(t)
	t.Chdir(root)
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = "" })
	var hosts []string
	for host := range hostvars {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	var vars, quoted, listed []string
	invYAML := "all:\n  hosts:\n"
	for _, host := range hosts {
		v := "{}"
		if policy := hostvars[host]; policy != "" {
			v = `{"deployment_availability":"` + policy + `"}`
		}
		vars = append(vars, `"`+host+`":`+v)
		quoted = append(quoted, `"`+host+`"`)
		listed = append(listed, "'    "+host+"'")
		invYAML += "    " + host + ": {}\n"
	}
	group := `{"hosts":[` + strings.Join(quoted, ",") + `]}`
	invJSON := `{"_meta":{"hostvars":{` + strings.Join(vars, ",") + `}},"leaf":` + group + `,"consumer":` + group + `}`
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "ansible-inventory"), []byte("#!/bin/sh\nprintf '%s\\n' '"+invJSON+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ansibleFixture := "#!/bin/sh\ncase \"$*\" in\n" +
		"  *--list-hosts*) printf '%s\\n' '  hosts (" + strconv.Itoa(len(hosts)) + "):' " + strings.Join(listed, " ") + "; exit 0 ;;\n" +
		"  *) printf '{\"plays\":[{\"tasks\":[{\"hosts\":{\"host-a\":{\"stdout\":\"unknown\",\"rc\":0}}}]}]}\\n' ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(binDir, "ansible"), []byte(ansibleFixture), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	inv := filepath.Join(t.TempDir(), "inventory.yml")
	if err := os.WriteFile(inv, []byte(invYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	return inv
}

// TestExecuteCatalogReconcileBatch_PreviewOnlyPersistsNothing: an accepted auto
// host var must not reach group_vars from a preview-only run, including the
// case where the main playbook was deferred (its core returns nil, not
// errPreviewOnlyStop).
func TestExecuteCatalogReconcileBatch_PreviewOnlyPersistsNothing(t *testing.T) {
	for _, tt := range []struct {
		name    string
		down    map[string]bool
		wantErr string // "" = the preview passes
	}{
		{name: "previewed", down: map[string]bool{}},
		{name: "every host deferred", down: map[string]bool{"host-a": true}, wantErr: "沒有預覽"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			inv := writeReconcileBatchFixture(t, map[string]string{"host-a": "optional"})
			workspace := t.TempDir()
			groupVars := filepath.Join(workspace, "group_vars", "all.yml")
			if err := os.MkdirAll(filepath.Dir(groupVars), 0o755); err != nil {
				t.Fatal(err)
			}
			const original = "# thanos_s3_target_host: 192.0.2.1\n"
			if err := os.WriteFile(groupVars, []byte(original), 0o644); err != nil {
				t.Fatal(err)
			}
			runner := ansible.NewRunner()
			runner.Binary = writeArgsFixture(t, filepath.Join(t.TempDir(), "args"))
			runner.Timeout = 5 * time.Second

			oldPrompt := activePromptAutomation
			activePromptAutomation = &promptAutomation{useDefaults: true, previewOnly: true}
			t.Cleanup(func() { activePromptAutomation = oldPrompt })
			oldProber := deployAvailabilityProber
			deployAvailabilityProber = fakeDownHostsProber(tt.down)
			t.Cleanup(func() { deployAvailabilityProber = oldProber })

			request := catalogDeploymentRequest{
				playbook: "consumer-apply.yml", inv: inv, extraVars: []string{"stage=sandbox"}, stage: "sandbox",
				componentHints: []string{"consumer"}, workspaceDir: workspace,
				acceptedAutoHostVars: []acceptedAutoHostVar{{Var: "thanos_s3_target_host", Value: "10.9.9.9"}},
			}
			var out bytes.Buffer
			// Assert the outcome too, so a fixture that broke early cannot pass vacuously.
			err := executeCatalogReconcileBatch(context.Background(), runner, &out, []catalogDeploymentRequest{request})
			if (tt.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("executeCatalogReconcileBatch() error = %v, want %q\n%s", err, tt.wantErr, out.String())
			}
			if data, err := os.ReadFile(groupVars); err != nil || string(data) != original {
				t.Fatalf("group_vars = %q (err %v), want it untouched by a preview-only run\n%s", data, err, out.String())
			}
		})
	}
}

// TestExecuteCatalogReconcileBatch_Force: reconcile --force previews and then
// applies each playbook in plan order, and persists accepted auto host vars.
func TestExecuteCatalogReconcileBatch_Force(t *testing.T) {
	inv := writeReconcileBatchFixture(t, map[string]string{"host-a": ""})
	workspace := t.TempDir()
	groupVars := filepath.Join(workspace, "group_vars", "all.yml")
	if err := os.MkdirAll(filepath.Dir(groupVars), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(groupVars, []byte("# thanos_s3_target_host: 192.0.2.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	argsPath := filepath.Join(t.TempDir(), "args")
	runner := ansible.NewRunner()
	runner.Binary = writeArgsFixture(t, argsPath)
	runner.Timeout = 5 * time.Second

	oldPrompt := activePromptAutomation
	activePromptAutomation = &promptAutomation{useDefaults: true, forceApply: true}
	t.Cleanup(func() { activePromptAutomation = oldPrompt })
	stubDeploymentAvailabilityAllReachable(t)

	request := catalogDeploymentRequest{
		playbook: "consumer-apply.yml", inv: inv, extraVars: []string{"stage=sandbox"}, stage: "sandbox",
		componentHints: []string{"consumer"}, workspaceDir: workspace,
		acceptedAutoHostVars: []acceptedAutoHostVar{{Var: "thanos_s3_target_host", Value: "10.9.9.9"}},
	}
	var out bytes.Buffer
	if err := executeCatalogReconcileBatch(context.Background(), runner, &out, []catalogDeploymentRequest{request}); err != nil {
		t.Fatalf("executeCatalogReconcileBatch() error = %v\n%s", err, out.String())
	}
	data, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	var runs []string
	for _, run := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if !strings.HasPrefix(run, "playbooks/preflight.yml ") {
			runs = append(runs, run)
		}
	}
	want := []struct {
		check    bool
		playbook string
	}{{true, "leaf-apply.yml"}, {false, "leaf-apply.yml"}, {true, "consumer-apply.yml"}, {false, "consumer-apply.yml"}}
	if len(runs) != len(want) {
		t.Fatalf("ansible-playbook runs = %q, want preview then apply of leaf, then consumer", runs)
	}
	for i, w := range want {
		if strings.HasPrefix(runs[i], "--check --diff ") != w.check || !strings.Contains(runs[i], w.playbook) {
			t.Fatalf("run %d = %q, want check=%v of %s", i, runs[i], w.check, w.playbook)
		}
	}
	if data, err := os.ReadFile(groupVars); err != nil || !strings.Contains(string(data), "thanos_s3_target_host: 10.9.9.9") {
		t.Fatalf("group_vars = %q (err %v), want the accepted auto host var persisted after apply", data, err)
	}
}

// TestRunCatalogPlaybookDeployEntry_DefaultsRefuseAmbiguousExactlyOne: with
// two hosts in an exactly-one component's group, the defaults driver must not
// pick one; it fails and names the candidates. A scripted --actions driver
// still answers the host select.
func TestRunCatalogPlaybookDeployEntry_DefaultsRefuseAmbiguousExactlyOne(t *testing.T) {
	inv := writeReconcileBatchFixture(t, map[string]string{"host-a": "", "host-b": ""})
	root, err := resolveContractRoot("")
	if err != nil {
		t.Fatal(err)
	}
	loader, err := contract.NewLoader(root)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, driver := range []*promptAutomation{
		{useDefaults: true, forceApply: true},
		{useDefaults: true, previewOnly: true},
	} {
		oldPrompt := activePromptAutomation
		activePromptAutomation = driver
		var requests []catalogDeploymentRequest
		entry := deployPlaybook{Key: "consumer", Playbook: "consumer-apply.yml", StageVar: "stage", DefaultGroup: "consumer", Reconcile: true}
		err := runCatalogPlaybookDeployEntry(context.Background(), ansible.NewRunner(), &bytes.Buffer{}, inv, "apply", catalog, entry, nil, deployInventorySnapshot{}, true, &requests)
		activePromptAutomation = oldPrompt
		if err == nil || !strings.Contains(err.Error(), "exactly-one") || !strings.Contains(err.Error(), "host-a, host-b") || len(requests) != 0 {
			t.Fatalf("forceApply=%v previewOnly=%v: error = %v, requests = %d; want a refusal naming both hosts", driver.forceApply, driver.previewOnly, err, len(requests))
		}
	}

	oldPrompt := activePromptAutomation
	activePromptAutomation = &promptAutomation{action: "reconcile", answers: []promptAnswer{
		{Prompt: "此元件要求 exactly-one", Select: "host-b"},
		{Prompt: "[consumer] 要套用到哪個 stage", Select: "sandbox"},
		{Prompt: "要限定只套用到某台主機嗎", Text: ""},
		{Prompt: "要只跑某幾個檢查項目嗎", Text: ""},
		{Prompt: "這次佈署需要密碼變數嗎", Select: "不需要"},
		{Prompt: "這次套用要手動輸入 sudo", Confirm: new(bool)},
		{Prompt: "還有其他 -e 變數要帶嗎", Text: ""},
	}}
	t.Cleanup(func() { activePromptAutomation = oldPrompt })
	var requests []catalogDeploymentRequest
	entry := deployPlaybook{Key: "consumer", Label: "consumer", Playbook: "consumer-apply.yml", StageVar: "stage", DefaultGroup: "consumer", Reconcile: true}
	if err := runCatalogPlaybookDeployEntry(context.Background(), ansible.NewRunner(), &bytes.Buffer{}, inv, "apply", catalog, entry, nil, deployInventorySnapshot{}, true, &requests); err != nil {
		t.Fatalf("scripted driver: error = %v", err)
	}
	if len(requests) != 1 || !slices.Contains(requests[0].extraVars, "target_group=host-b") {
		t.Fatalf("scripted driver: requests = %+v, want target_group=host-b", requests)
	}
}

// TestRunReconcileInteractive_RelativeDirResolvesInventoryOnce: under the
// defaults driver a relative --dir must not be joined twice onto the default
// inventory path (the interactive validator used to catch that).
func TestRunReconcileInteractive_RelativeDirResolvesInventoryOnce(t *testing.T) {
	prev := []any{reconcileStdinIsTerminal, reconcilePreviewOnlyFlag, reconcileDirFlag, reconcileInventoryFlag, reconcileTimeoutFlag, activePromptAutomation}
	t.Cleanup(func() {
		reconcileStdinIsTerminal = prev[0].(func() bool)
		reconcilePreviewOnlyFlag = prev[1].(bool)
		reconcileDirFlag, reconcileInventoryFlag, reconcileTimeoutFlag = prev[2].(string), prev[3].(string), prev[4].(string)
		activePromptAutomation, _ = prev[5].(*promptAutomation)
	})
	work := t.TempDir()
	t.Chdir(work)
	if err := os.MkdirAll("sub", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("sub", "inventory.yml"), []byte("all: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = "" })
	argsPath := filepath.Join(t.TempDir(), "inventory-args")
	binDir := t.TempDir()
	// Record the -i argument, then fail: the test only needs the resolved path.
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + argsPath + "\nexit 1\n"
	if err := os.WriteFile(filepath.Join(binDir, "ansible-inventory"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	reconcileStdinIsTerminal = func() bool { return false }
	activePromptAutomation = nil
	reconcilePreviewOnlyFlag = true
	reconcileDirFlag, reconcileInventoryFlag, reconcileTimeoutFlag = "sub", "inventory.yml", "30m"
	command := &cobra.Command{}
	command.SetContext(context.Background())
	_ = runReconcileInteractive(command)

	data, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("ansible-inventory never ran: %v", err)
	}
	if !strings.Contains(string(data), "-i sub/inventory.yml") || strings.Contains(string(data), "sub/sub/") {
		t.Fatalf("ansible-inventory args = %q, want -i sub/inventory.yml", data)
	}
}
