package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// hotfixSkewHarness runs the real `pilot hotfix wazuh-agent-skew` entry point against a fake
// ansible-playbook. The playbook's stdout is the real ansible capture of the playbook's own
// marker tasks (internal/hotfix/testdata, kept equal to the playbook by internal/spec
// TestWazuhAgentHotfixMarkersAreTheRealCapture), so the whole path from the cobra flags through
// the parse to the exit status is exercised, not just the parser. The capture has four agent hosts:
// agent-new (newer than the manager), agent-ok (compatible), agent-none (no agent) and agent-left
// (no package, audit plugin still running: residue).
type hotfixSkewHarness struct {
	t       *testing.T
	argsLog string
}

func newHotfixSkewHarness(t *testing.T, observeOut, applyOut string, observeExit, applyExit int) *hotfixSkewHarness {
	t.Helper()
	bin := t.TempDir()
	work := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(work, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	observe := write("observe.out", observeOut)
	apply := write("apply.out", applyOut)
	argsLog := filepath.Join(work, "args.log")
	inventory := `{"_meta":{"hostvars":{}},"all":{"children":["wazuh-fim","wazuh-manager"]},` +
		`"wazuh-fim":{"hosts":["agent-new","agent-ok","agent-none","agent-left"]},"wazuh-manager":{"hosts":["mgr-1"]}}`
	files := map[string]string{
		"ansible-inventory": "#!/bin/sh\nprintf '%s\\n' '" + inventory + "'\n",
		"ansible-playbook": `#!/bin/sh
echo "$*" >> '` + argsLog + `'
case "$*" in
  *pilot_hotfix_mode=observe*) cat '` + observe + `'; exit ` + strconv.Itoa(observeExit) + ` ;;
  *) cat '` + apply + `'; exit ` + strconv.Itoa(applyExit) + ` ;;
esac
`,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := os.WriteFile(filepath.Join(work, "inventory.yml"), []byte("all: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := struct {
		dir, inv, timeout, stage, attested, limit string
		force, preview                            bool
		tty                                       func() bool
		data                                      string
		prompt                                    *promptAutomation
	}{hotfixSkewDirFlag, hotfixSkewInventoryFlag, hotfixSkewTimeoutFlag, stageFlag, stagingAttestedHoursFlag, limitFlag,
		hotfixSkewForceFlag, hotfixSkewPreviewOnlyFlag, hotfixStdinIsTerminal, dataDir, activePromptAutomation}
	t.Cleanup(func() {
		hotfixSkewDirFlag, hotfixSkewInventoryFlag, hotfixSkewTimeoutFlag = prev.dir, prev.inv, prev.timeout
		stageFlag, stagingAttestedHoursFlag, limitFlag = prev.stage, prev.attested, prev.limit
		hotfixSkewForceFlag, hotfixSkewPreviewOnlyFlag, hotfixStdinIsTerminal = prev.force, prev.preview, prev.tty
		dataDir, activePromptAutomation = prev.data, prev.prompt
	})
	dataDir = t.TempDir()
	hotfixSkewDirFlag, hotfixSkewInventoryFlag, hotfixSkewTimeoutFlag = work, "inventory.yml", "30s"
	stageFlag, stagingAttestedHoursFlag, limitFlag = "", "", ""
	hotfixSkewForceFlag, hotfixSkewPreviewOnlyFlag = false, false
	hotfixStdinIsTerminal = func() bool { return false }
	activePromptAutomation = nil
	return &hotfixSkewHarness{t: t, argsLog: argsLog}
}

func (h *hotfixSkewHarness) run() (string, error) {
	h.t.Helper()
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runHotfixWazuhAgentSkew(cmd, nil)
	return out.String(), err
}

// calls returns one entry per ansible-playbook invocation.
func (h *hotfixSkewHarness) calls() []string {
	h.t.Helper()
	data, err := os.ReadFile(h.argsLog)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		h.t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func realHotfixMarkers(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "internal", "hotfix", "testdata", "ansible-debug-markers.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func withoutLines(text, marker string) string {
	var keep []string
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, marker) {
			keep = append(keep, line)
		}
	}
	return strings.Join(keep, "\n")
}

func TestHotfixSkewPreviewOnlyPlansAndChangesNothing(t *testing.T) {
	markers := realHotfixMarkers(t)
	h := newHotfixSkewHarness(t, markers, markers, 0, 0)
	hotfixSkewPreviewOnlyFlag = true
	out, err := h.run()
	if err != nil {
		t.Fatalf("error = %v\n%s", err, out)
	}
	calls := h.calls()
	if len(calls) != 1 || !strings.Contains(calls[0], "pilot_hotfix_mode=observe") {
		t.Fatalf("ansible-playbook calls = %q, want exactly the read-only observe run", calls)
	}
	if !strings.Contains(calls[0], "playbooks/apply/wazuh-fim-agent-skew-hotfix.yml") {
		t.Errorf("wrong playbook: %q", calls[0])
	}
	for _, want := range []string{"agent-new", "4.14.9-1", "agent-left", "清除遺留的 audit plugin（套件已不在）",
		"2 台主機需要處理（移除 agent 1 台、清除遺留 audit plugin 1 台）", "沒有變更任何東西"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestHotfixSkewNothingNewerAsksNothingAndRunsNothing(t *testing.T) {
	markers := strings.ReplaceAll(strings.ReplaceAll(realHotfixMarkers(t), "skewed=true", "skewed=false"), "residue=true", "residue=false")
	h := newHotfixSkewHarness(t, markers, markers, 0, 0)
	hotfixSkewForceFlag = true
	out, err := h.run()
	if err != nil {
		t.Fatalf("error = %v\n%s", err, out)
	}
	if calls := h.calls(); len(calls) != 1 {
		t.Fatalf("calls = %q, want only the observe run when nothing needs the hotfix", calls)
	}
	if !strings.Contains(out, "什麼都不需要做") {
		t.Errorf("output lacks the nothing-to-do message:\n%s", out)
	}
}

func TestHotfixSkewForceObservesThenAppliesWithTheStage(t *testing.T) {
	markers := realHotfixMarkers(t)
	h := newHotfixSkewHarness(t, markers, markers, 0, 0)
	hotfixSkewForceFlag = true
	out, err := h.run()
	if err != nil {
		t.Fatalf("error = %v\n%s", err, out)
	}
	calls := h.calls()
	if len(calls) != 2 {
		t.Fatalf("calls = %q, want observe then apply", calls)
	}
	if strings.Contains(calls[1], "pilot_hotfix_mode=observe") || !strings.Contains(calls[1], "stage=sandbox") {
		t.Errorf("apply call = %q, want stage=sandbox and no observe mode", calls[1])
	}
	if !strings.Contains(out, "已移除 agent：agent-new") || !strings.Contains(out, "pilot deploy") {
		t.Errorf("output lacks the result and the redeploy hint:\n%s", out)
	}
	// the residue host is reported on its own line and is not counted among the removed agents
	if !strings.Contains(out, "已清除遺留的 audit plugin（套件先前已移除）：agent-left") || strings.Contains(out, "已移除 agent：agent-left") {
		t.Errorf("the residue host is not reported as cleaned:\n%s", out)
	}
}

// What the operator confirmed (every actionable host of the plan, skewed and residue alike) is handed to the
// apply run as a JSON object value, so a host that became actionable after the plan refuses the run before
// anything is changed; the read-only observe run carries no such restriction (and no stage flags).
func TestHotfixSkewHandsTheConfirmedHostsToTheApplyRunOnly(t *testing.T) {
	markers := realHotfixMarkers(t)
	h := newHotfixSkewHarness(t, markers, markers, 0, 0)
	hotfixSkewForceFlag = true
	if out, err := h.run(); err != nil {
		t.Fatalf("error = %v\n%s", err, out)
	}
	calls := h.calls()
	if len(calls) != 2 {
		t.Fatalf("calls = %q", calls)
	}
	const want = `{"pilot_hotfix_confirmed_hosts":["agent-left","agent-new"]}`
	if !strings.Contains(calls[1], "-e "+want) {
		t.Errorf("the apply call does not carry the confirmed hosts as a JSON object value %s: %q", want, calls[1])
	}
	if strings.Contains(calls[0], "pilot_hotfix_confirmed_hosts") {
		t.Errorf("the observe call must not carry the confirmed hosts: %q", calls[0])
	}
	if strings.Contains(calls[1], "pilot_hotfix_confirmed_hosts=") {
		t.Errorf("the confirmed hosts must never be passed as key=[...]: %q", calls[1])
	}
}

// Only a residue host needs the hotfix: it is planned, confirmed and reported as a cleanup, never as a
// removed agent, and the prompt does not tell the operator a package will be uninstalled.
func TestHotfixSkewResidueOnlyIsPlannedAndReportedAsACleanup(t *testing.T) {
	markers := strings.ReplaceAll(realHotfixMarkers(t), "skewed=true", "skewed=false")
	h := newHotfixSkewHarness(t, markers, markers, 0, 0)
	hotfixSkewForceFlag = true
	out, err := h.run()
	if err != nil {
		t.Fatalf("error = %v\n%s", err, out)
	}
	calls := h.calls()
	if len(calls) != 2 || !strings.Contains(calls[1], `{"pilot_hotfix_confirmed_hosts":["agent-left"]}`) {
		t.Fatalf("calls = %q, want observe then an apply for the residue host alone", calls)
	}
	if strings.Contains(out, "已移除 agent：") {
		t.Errorf("a residue host is reported as a removed agent:\n%s", out)
	}
	if !strings.Contains(out, "已清除遺留的 audit plugin") || !strings.Contains(out, "agent-left") {
		t.Errorf("the cleanup is not reported:\n%s", out)
	}
	if text := hotfixSkewConfirmText(0, 1); strings.Contains(text, "卸載") || !strings.Contains(text, "audit plugin") {
		t.Errorf("the prompt for a residue-only plan is wrong: %q", text)
	}
	if text := hotfixSkewConfirmText(2, 0); !strings.Contains(text, "不可復原") || strings.Contains(text, "audit plugin") {
		t.Errorf("the prompt for a skewed-only plan is wrong: %q", text)
	}
	if text := hotfixSkewConfirmText(2, 1); !strings.Contains(text, "3 台") || !strings.Contains(text, "audit plugin") || !strings.Contains(text, "不可復原") {
		t.Errorf("the prompt for a mixed plan is wrong: %q", text)
	}
}

// An apply run whose report cannot be read (a playbook that does not say whether a host was residue) is
// refused, never taken as success.
func TestHotfixSkewRefusesAnApplyReportItCannotRead(t *testing.T) {
	markers := realHotfixMarkers(t)
	h := newHotfixSkewHarness(t, markers, strings.ReplaceAll(markers, " residue=true", ""), 0, 0)
	hotfixSkewForceFlag = true
	out, err := h.run()
	if err == nil || !strings.Contains(err.Error(), "不當作成功") {
		t.Fatalf("error = %v, want a refusal to count an unreadable report as success\n%s", err, out)
	}
}

func TestHotfixSkewPassesLimitAndStageToThePlaybook(t *testing.T) {
	markers := realHotfixMarkers(t)
	h := newHotfixSkewHarness(t, markers, markers, 0, 0)
	hotfixSkewForceFlag = true
	limitFlag, stageFlag, stagingAttestedHoursFlag = "agent-new", "prod", "12"
	if out, err := h.run(); err != nil {
		t.Fatalf("error = %v\n%s", err, out)
	}
	calls := h.calls()
	if len(calls) != 2 {
		t.Fatalf("calls = %q", calls)
	}
	for i, call := range calls {
		if !strings.Contains(call, "--limit agent-new") {
			t.Errorf("call %d lacks --limit: %q", i, call)
		}
	}
	for _, want := range []string{"stage=prod", "confirm_prod=true", "staging_attested_within_hours=12"} {
		if !strings.Contains(calls[1], want) {
			t.Errorf("apply call lacks %q: %q", want, calls[1])
		}
	}
	if strings.Contains(calls[0], "stage=") {
		t.Errorf("the read-only observe run must not carry stage flags: %q", calls[0])
	}
}

// Success is only what the run reported: a planned host the apply never reported removed
// makes the command fail, and the failing exit codes are surfaced instead of swallowed.
func TestHotfixSkewFailsWhenAHostIsNotReportedRemoved(t *testing.T) {
	markers := realHotfixMarkers(t)
	noResult := withoutLines(markers, "PILOT_HOTFIX_RESULT")
	h := newHotfixSkewHarness(t, markers, noResult, 0, 0)
	hotfixSkewForceFlag = true
	out, err := h.run()
	if err == nil || !strings.Contains(err.Error(), "agent-new") || !strings.Contains(err.Error(), "agent-left") {
		t.Fatalf("error = %v, want a failure naming agent-new and agent-left\n%s", err, out)
	}
	if !strings.Contains(out, "沒有回報完成") {
		t.Errorf("output does not say the host was not reported done:\n%s", out)
	}
}

func TestHotfixSkewSurfacesAFailedPlaybookExit(t *testing.T) {
	markers := realHotfixMarkers(t)
	t.Run("observe fails: nothing is applied", func(t *testing.T) {
		h := newHotfixSkewHarness(t, markers, markers, 2, 0)
		hotfixSkewForceFlag = true
		if _, err := h.run(); err == nil || !strings.Contains(err.Error(), "結束碼 2") {
			t.Fatalf("error = %v", err)
		}
		if calls := h.calls(); len(calls) != 1 {
			t.Fatalf("calls = %q, want only the failed observe run", calls)
		}
	})
	t.Run("apply fails", func(t *testing.T) {
		h := newHotfixSkewHarness(t, markers, markers, 0, 2)
		hotfixSkewForceFlag = true
		if _, err := h.run(); err == nil || !strings.Contains(err.Error(), "結束碼 2") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestHotfixSkewRefusesAnObservationItCannotRead(t *testing.T) {
	h := newHotfixSkewHarness(t, "PLAY RECAP\n", "", 0, 0)
	hotfixSkewForceFlag = true
	if _, err := h.run(); err == nil || !strings.Contains(err.Error(), "整次拒絕") {
		t.Fatalf("error = %v, want a whole-run refusal", err)
	}
	if calls := h.calls(); len(calls) != 1 {
		t.Fatalf("calls = %q, an unreadable observation must never lead to an apply", calls)
	}
}

func TestHotfixSkewFlagValidation(t *testing.T) {
	markers := realHotfixMarkers(t)
	h := newHotfixSkewHarness(t, markers, markers, 0, 0)
	hotfixSkewForceFlag, hotfixSkewPreviewOnlyFlag = true, true
	if _, err := h.run(); err == nil || !strings.Contains(err.Error(), "--force 不能與 --preview-only") {
		t.Fatalf("--force --preview-only: error = %v", err)
	}
	hotfixSkewForceFlag, hotfixSkewPreviewOnlyFlag = false, false
	stageFlag = "prod"
	if _, err := h.run(); err == nil || !strings.Contains(err.Error(), "--staging-attested-within-hours") {
		t.Fatalf("--stage prod without attestation: error = %v", err)
	}
	stageFlag, limitFlag = "", "a b"
	if _, err := h.run(); err == nil || !strings.Contains(err.Error(), "--limit") {
		t.Fatalf("bad --limit: error = %v", err)
	}
	limitFlag = ""
	if _, err := h.run(); err == nil || !strings.Contains(err.Error(), "TTY") {
		t.Fatalf("no TTY and no --force/--preview-only: error = %v", err)
	}
	if calls := h.calls(); len(calls) != 0 {
		t.Fatalf("a rejected invocation ran ansible-playbook: %q", calls)
	}
}

func TestHotfixSkewIsRegisteredUnderHotfix(t *testing.T) {
	sub, _, err := rootCmd.Find([]string{"hotfix", "wazuh-agent-skew"})
	if err != nil || sub != hotfixWazuhAgentSkewCmd {
		t.Fatalf("pilot hotfix wazuh-agent-skew is not reachable: %v", err)
	}
	// The flags a deploy user already knows.
	for _, name := range []string{"dir", "inventory", "timeout", "limit", "stage", "staging-attested-within-hours", "force", "preview-only"} {
		if sub.Flags().Lookup(name) == nil {
			t.Errorf("missing deploy-compatible flag --%s", name)
		}
	}
}

// Declining the confirmation (the default answer is No) changes nothing: only the read-only observe
// run happened, the command exits cleanly, and says so. The real terminal widget is not exercised;
// the defaults driver answers the same prompt id the widget would be asked.
func TestHotfixSkewDecliningTheConfirmationChangesNothing(t *testing.T) {
	markers := realHotfixMarkers(t)
	h := newHotfixSkewHarness(t, markers, markers, 0, 0)
	hotfixStdinIsTerminal = func() bool { return true }
	activePromptAutomation = &promptAutomation{useDefaults: true}
	out, err := h.run()
	if err != nil {
		t.Fatalf("declining must be a clean exit: %v\n%s", err, out)
	}
	if calls := h.calls(); len(calls) != 1 || !strings.Contains(calls[0], "pilot_hotfix_mode=observe") {
		t.Fatalf("calls = %q, want only the read-only observe run", calls)
	}
	if !strings.Contains(out, "已取消，沒有變更任何東西") {
		t.Errorf("output does not say nothing was changed:\n%s", out)
	}
}
