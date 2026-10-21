package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/kjelly/pilot/internal/diagnose"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestDiagnoseCommandEvidence_PreservesFailureKinds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		result  diagnose.AdHocResult
		outcome string
		known   bool
	}{
		{"nonzero", diagnose.AdHocResult{RC: 7, RCKnown: true, Failed: true, Stdout: "out", Stderr: "err", Message: "non-zero return code"}, "command_nonzero", true},
		{"unreachable", diagnose.AdHocResult{Unreachable: true, Message: "connection failed"}, "unreachable", false},
		{"timeout", diagnose.AdHocResult{RC: 7, RCKnown: true, Stdout: "partial", Stderr: "err", RunErr: context.DeadlineExceeded}, "unknown", true},
		{"decoder", diagnose.AdHocResult{RunErr: errors.New("malformed callback")}, "unknown", false},
		// This phrase was captured by the issue reporter from a real ipa call.
		{"kerberos", diagnose.AdHocResult{RC: 1, RCKnown: true, Failed: true, Stderr: "ipa: ERROR: did not receive Kerberos credentials"}, "auth_required", true},
		{"missing_rc", diagnose.AdHocResult{Failed: true, Message: "module failed"}, "unknown", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := stepEvidenceList([]diagnose.StepResult{{Result: tc.result}})[0]
			if got.OK || got.Outcome != tc.outcome || got.RCKnown != tc.known || got.Stdout != tc.result.Stdout || got.Stderr != tc.result.Stderr || got.Message != tc.result.Message || got.Unreachable != tc.result.Unreachable || got.Failed != tc.result.Failed {
				t.Fatalf("evidence = %+v", got)
			}
		})
	}
}

func TestDiagnoseOutputSafety_AllStreamsAndNestedStrings(t *testing.T) {
	secret := "password=stream-secret "
	ev := commandEvidence(diagnose.AdHocResult{RCKnown: true, Stdout: secret, Stderr: secret, Message: secret, RunErr: errors.New(secret)})
	if !ev.Redacted {
		t.Fatal("missing redacted flag")
	}
	encoded, _ := json.Marshal(ev)
	if strings.Contains(string(encoded), "stream-secret") {
		t.Fatal("evidence leaked secret")
	}
	large := strings.Repeat("界", maxDiagnosticResponseBytes)
	type report struct {
		diagnoseAuditStatus
		Nested []map[string]string `json:"nested"`
		Count  uint64              `json:"count"`
	}
	got, err := sanitizeDiagnoseOutput(report{Count: 1<<63 + 1, Nested: []map[string]string{{"stderr": secret, "detail": large, "stdout": "  retain whitespace\n", "password": "nested-secret"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Count != 1<<63+1 || !got.Redacted || !got.Truncated || strings.Contains(got.Nested[0]["stderr"], "stream-secret") || got.Nested[0]["password"] != "[REDACTED]" || len(got.Nested[0]["detail"]) > maxDiagnosticResponseBytes || !utf8.ValidString(got.Nested[0]["detail"]) || got.Nested[0]["stdout"] != "  retain whitespace\n" {
		t.Fatalf("safety flags=%v/%v, nested output invalid", got.Redacted, got.Truncated)
	}
}

func connectDiagnoseTestServer(t *testing.T, server *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "diagnose-result-test", Version: "1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func TestDiagnoseWire_ErrorHasNoZeroStructuredResult(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "diagnose-test", Version: "1"}, nil)
	for _, name := range []string{"pilot_diagnose_error", "pilot_diagnose_returned_error"} {
		addRecoveredTool(server, &mcp.Tool{Name: name}, func(context.Context, *mcp.CallToolRequest, diagnoseRunInput) (*mcp.CallToolResult, diagnoseRunOutput, error) {
			if name == "pilot_diagnose_returned_error" {
				return nil, diagnoseRunOutput{}, errors.New("password=error-secret")
			}
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: "password=error-secret"}), diagnoseRunOutput{}, nil
		})
	}
	session := connectDiagnoseTestServer(t, server)
	for _, name := range []string{"pilot_diagnose_error", "pilot_diagnose_returned_error"} {
		t.Run(name, func(t *testing.T) {
			got, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: map[string]any{"host": "web1", "command": "id"}})
			if err != nil {
				t.Fatal(err)
			}
			if !got.IsError || got.StructuredContent != nil || len(got.Content) != 1 {
				t.Fatalf("wire result = %+v", got)
			}
			text := got.Content[0].(*mcp.TextContent).Text
			var toolErr mcpToolError
			if err := json.Unmarshal([]byte(text), &toolErr); err != nil {
				t.Fatalf("error content must remain valid JSON: %v: %s", err, text)
			}
			wantCode := mcpErrInvalidParam
			if name == "pilot_diagnose_returned_error" {
				wantCode = mcpErrInternal
			}
			if toolErr.Code != wantCode || !toolErr.Redacted || strings.Contains(text, "error-secret") {
				t.Fatalf("error content = %s", text)
			}
		})
	}
}

func TestDiagnoseRunWire_ActualLocalAnsible(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t)
	opts := baseDiagnoseOpts(t, inv, nil)
	opts.StepTimeout = 20 * time.Second
	opts.AnsibleRuntime.Env = append(opts.AnsibleRuntime.Env, "ANSIBLE_REMOTE_TEMP="+t.TempDir())
	// Ansible versions change msg wording. Compare with the actual callback,
	// independently of Pilot's decoder, rather than pinning external prose.
	callbacks := make(chan string, 1)
	runner := realDiagnoseAdHocRunner()
	opts.AdHocRunner = func(ctx context.Context, args []string, timeout int) (string, int, error) {
		raw, rc, err := runner(ctx, args, timeout)
		callbacks <- raw
		return raw, rc, err
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "diagnose-test", Version: "1"}, nil)
	registerDiagnoseRunTool(server, opts)
	session := connectDiagnoseTestServer(t, server)
	command := `python3 -c 'import sys; print("password=local-secret"); print("diagnostic stderr", file=sys.stderr); sys.exit(7)'`
	got, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "pilot_diagnose_run", Arguments: map[string]any{"host": "web1", "command": command}})
	if err != nil {
		t.Fatal(err)
	}
	if got.IsError {
		t.Fatalf("remote nonzero must remain diagnostic data: %+v", got)
	}
	var callback struct {
		Plays []struct {
			Tasks []struct {
				Hosts map[string]struct {
					Message string `json:"msg"`
				} `json:"hosts"`
			} `json:"tasks"`
		} `json:"plays"`
	}
	if err := json.Unmarshal([]byte(<-callbacks), &callback); err != nil {
		t.Fatalf("decode actual callback: %v", err)
	}
	var expectedMessage string
	for _, play := range callback.Plays {
		for _, task := range play.Tasks {
			if host, ok := task.Hosts["web1"]; ok {
				expectedMessage = host.Message
			}
		}
	}
	if expectedMessage == "" {
		t.Fatal("actual failed-command callback is missing its message")
	}
	out := decodeStructured[diagnoseRunOutput](t, got)
	if out.RC != 7 || !out.RCKnown || !out.Failed || out.Outcome != "command_nonzero" || out.Stdout != "password= [REDACTED]" || out.Stderr != "diagnostic stderr" || out.Message != expectedMessage || !out.Redacted || out.Error != "" {
		t.Fatalf("actual Ansible result = %+v", out)
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "local-secret") {
		t.Fatalf("wire leaked secret: %s", data)
	}
	if _, err := os.Stat(filepath.Join(out.AuditDirectory, "record.json")); err != nil {
		t.Fatal(err)
	}
}

func TestDiagnoseRunWire_CapturedAndUnknownOutcomes(t *testing.T) {
	requireRealAnsible(t)
	captures := map[string]string{}
	for _, name := range []string{"both", "stderr", "unreachable"} {
		data, err := os.ReadFile("../../../internal/diagnose/testdata/adhoc/" + name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		captures[name] = strings.ReplaceAll(string(data), `"localhost"`, `"web1"`)
	}
	runner := func(_ context.Context, args []string, _ int) (string, int, error) {
		key := args[len(args)-1]
		if key == "timeout" {
			return captures["both"], 2, context.DeadlineExceeded
		}
		if key == "malformed" {
			return "broken callback", 0, nil
		}
		return captures[key], 2, nil
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "diagnose-test", Version: "1"}, nil)
	registerDiagnoseRunTool(server, baseDiagnoseOpts(t, writeDiagnoseFixtureInventory(t), runner))
	session := connectDiagnoseTestServer(t, server)
	for _, tc := range []struct {
		name, outcome, stdout, stderr string
		known                         bool
	}{
		{"both", "command_nonzero", "out", "err", true},
		{"stderr", "command_nonzero", "", "stderr only", true},
		{"unreachable", "unreachable", "", "", false},
		{"timeout", "unknown", "out", "err", true},
		{"malformed", "unknown", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "pilot_diagnose_run", Arguments: map[string]any{"host": "web1", "command": tc.name}})
			if err != nil {
				t.Fatal(err)
			}
			out := decodeStructured[diagnoseRunOutput](t, got)
			if got.IsError || out.Outcome != tc.outcome || out.Stdout != tc.stdout || out.Stderr != tc.stderr || out.RCKnown != tc.known {
				t.Fatalf("result = %+v, isError=%v", out, got.IsError)
			}
			if tc.outcome == "unknown" && out.Error == "" {
				t.Fatal("unknown needs a failure reason")
			}
			if tc.name == "stderr" && out.Message != "non-zero return code" {
				t.Fatalf("message = %q", out.Message)
			}
			if tc.name == "unreachable" && (!out.Unreachable || out.Message == "") {
				t.Fatalf("unreachable facts = %+v", out)
			}
		})
	}
}

func TestDiagnoseSynthesizedFailures_Captured(t *testing.T) {
	requireRealAnsible(t)
	for _, name := range []string{"unreachable", "module-failure"} {
		for _, keepKnownSSSD := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/known_sssd=%v", name, keepKnownSSSD), func(t *testing.T) {
				data, err := os.ReadFile("../../../internal/diagnose/testdata/adhoc/" + name + ".json")
				if err != nil {
					t.Fatal(err)
				}
				raw := strings.ReplaceAll(string(data), `"localhost"`, `"web1"`)
				runner := func(_ context.Context, args []string, _ int) (string, int, error) {
					if keepKnownSSSD && args[len(args)-1] == "systemctl is-active sssd" {
						return diagnoseOKDoc(t, "web1", 0, "active"), 0, nil
					}
					return raw, 2, nil
				}
				opts := baseDiagnoseOpts(t, writeDiagnoseFixtureInventory(t), runner)
				_, sudo, err := diagnoseSudoHandler(opts)(context.Background(), &mcp.CallToolRequest{}, diagnoseSudoInput{Host: "web1", User: "alice"})
				if err != nil {
					t.Fatal(err)
				}
				if sudo.SssdActive != keepKnownSSSD || sudo.HasKerberosMachineIdentity || sudo.AccountResolvesViaSSSD || sudo.CentralSudoRuleGrantsAccess || !strings.Contains(sudo.Verdict, "insufficient evidence") {
					t.Fatalf("sudo falsely synthesized success: %+v", sudo)
				}
				_, login, err := diagnoseLoginHandler(opts)(context.Background(), &mcp.CallToolRequest{}, diagnoseLoginInput{Host: "web1", Users: []string{"alice"}})
				if err != nil {
					t.Fatal(err)
				}
				if login.SssdActive != keepKnownSSSD || login.HasKerberosMachineIdentity || len(login.Users) != 1 || login.Users[0].AccountResolvesViaSSSD || login.Users[0].CentralSudoRuleGrantsAccess || !strings.Contains(login.HostVerdict, "insufficient evidence") {
					t.Fatalf("login falsely synthesized success: %+v", login)
				}
				if sudo.Steps[len(sudo.Steps)-1].Message == "" || login.Steps[len(login.Steps)-1].Message == "" {
					t.Fatal("failure reason disappeared")
				}
			})
		}
	}
}

func TestRealDiagnoseAdHocRunner_WaitDelayRetainsCallback(t *testing.T) {
	data, err := os.ReadFile("../../../internal/diagnose/testdata/adhoc/both.json")
	if err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	script := "#!/bin/sh\ncat <<'PILOT_CALLBACK'\n" + string(data) + "\nPILOT_CALLBACK\nsleep 4 &\nexit 0\n"
	if err := os.WriteFile(filepath.Join(binDir, "ansible"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	results := diagnose.RunSteps(context.Background(), realDiagnoseAdHocRunner(), "unused", "localhost", []diagnose.Step{{ID: "pipe-held", Module: "command", Command: "unused"}}, 10*time.Second)
	got := results[0].Result
	if !errors.Is(got.RunErr, exec.ErrWaitDelay) || got.Stdout != "out" || got.Stderr != "err" || got.RC != 7 || !got.RCKnown {
		t.Fatalf("wait-delay discarded complete callback: %+v", got)
	}
}

func TestDiagnoseCommandEvidence_ExecutionFailuresStayUnknown(t *testing.T) {
	for _, result := range []diagnose.AdHocResult{
		{RC: 7, RCKnown: true, ModuleFailed: true, Failed: true, Message: "did not receive Kerberos credentials"},
		{RC: 7, RCKnown: true, CommandStartFailed: true, Failed: true},
	} {
		evidence := commandEvidence(result)
		if evidence.OK || evidence.RCKnown || evidence.RC != 0 || evidence.Outcome != "unknown" || evidence.Error == "" {
			t.Fatalf("execution failure classified as command result=%+v", evidence)
		}
	}
	evidence := commandEvidence(diagnose.AdHocResult{ModuleFailed: true, ModuleStdout: "password=module-secret " + strings.Repeat("界", maxDiagnosticResponseBytes), ModuleStderr: "token=module-token", LauncherRC: 127, LauncherRCKnown: true})
	data, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.Redacted || !evidence.Truncated || len(evidence.ModuleStdout) > maxDiagnosticResponseBytes || !utf8.ValidString(evidence.ModuleStdout) || strings.Contains(string(data), "module-secret") || strings.Contains(string(data), "module-token") || evidence.LauncherRC != 127 || !evidence.LauncherRCKnown {
		t.Fatalf("module diagnostics not safely preserved=%+v", evidence)
	}
}

func TestDiagnoseRunWire_ActualExecutionLayerFailures(t *testing.T) {
	requireRealAnsible(t)
	for _, tc := range []struct {
		name                      string
		launcherRC                int
		moduleFailed, startFailed bool
		commandRC                 int
	}{
		{"bad-interpreter", 127, true, false, 0},
		{"missing-executable", 2, false, true, 0},
		{"not-executable", 13, false, true, 0},
		{"command-rc7", 0, false, false, 7},
		{"command-rc127", 0, false, false, 127},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv := writeDiagnoseFixtureInventory(t)
			interpreter := "/usr/bin/python3"
			command := "/bin/true"
			switch tc.name {
			case "bad-interpreter":
				interpreter = "/nonexistent/pilot-review-python"
			case "missing-executable":
				command = "/nonexistent/pilot-review-command"
			case "not-executable":
				path := filepath.Join(t.TempDir(), "not-executable")
				if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				command = path
			case "command-rc127":
				command = `/bin/sh -c 'exit 127'`
			case "command-rc7":
				command = `python3 -c 'import sys; print("out"); print("err", file=sys.stderr); sys.exit(7)'`
			}
			inventory := fmt.Sprintf("all:\n  hosts:\n    web1: {ansible_connection: local, ansible_host: 127.0.0.1, ansible_python_interpreter: %s}\n", interpreter)
			if err := os.WriteFile(inv, []byte(inventory), 0o600); err != nil {
				t.Fatal(err)
			}
			opts := baseDiagnoseOpts(t, inv, nil)
			opts.StepTimeout = 20 * time.Second
			opts.AnsibleRuntime.Env = append(opts.AnsibleRuntime.Env, "ANSIBLE_REMOTE_TEMP="+t.TempDir())
			callbacks := make(chan string, 1)
			runner := realDiagnoseAdHocRunner()
			opts.AdHocRunner = func(ctx context.Context, args []string, timeout int) (string, int, error) {
				raw, rc, err := runner(ctx, args, timeout)
				callbacks <- raw
				return raw, rc, err
			}
			server := mcp.NewServer(&mcp.Implementation{Name: "execution-layer-test", Version: "1"}, nil)
			registerDiagnoseRunTool(server, opts)
			session := connectDiagnoseTestServer(t, server)
			wire, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "pilot_diagnose_run", Arguments: map[string]any{"host": "web1", "command": command}})
			if err != nil {
				t.Fatal(err)
			}
			if wire.IsError {
				t.Fatalf("diagnostic data became MCP error=%+v", wire)
			}
			raw := <-callbacks
			// Read callback fields independently of the production decoder.
			var callback struct {
				Plays []struct {
					Tasks []struct {
						Hosts map[string]struct {
							Message      string `json:"msg"`
							ModuleStdout string `json:"module_stdout"`
							ModuleStderr string `json:"module_stderr"`
						} `json:"hosts"`
					} `json:"tasks"`
				} `json:"plays"`
			}
			if err := json.Unmarshal([]byte(raw), &callback); err != nil {
				t.Fatal(err)
			}
			original := callback.Plays[0].Tasks[0].Hosts["web1"]
			out := decodeStructured[diagnoseRunOutput](t, wire)
			if out.Message != original.Message || out.ModuleStdout != original.ModuleStdout || out.ModuleStderr != original.ModuleStderr || out.ModuleFailed != tc.moduleFailed || out.CommandStartFailed != tc.startFailed {
				t.Fatalf("wire dropped execution-layer diagnostics=%+v", out)
			}
			auditData, err := os.ReadFile(filepath.Join(out.AuditDirectory, "record.json"))
			if err != nil {
				t.Fatal(err)
			}
			var record diagnoseAuditRecord
			if err := json.Unmarshal(auditData, &record); err != nil {
				t.Fatal(err)
			}
			if len(record.Steps) != 1 {
				t.Fatalf("audit steps=%+v", record.Steps)
			}
			audit := record.Steps[0]
			if audit.RCKnown != out.RCKnown || audit.RC != out.RC || audit.LauncherRC != out.LauncherRC || audit.LauncherRCKnown != out.LauncherRCKnown || audit.ModuleFailed != out.ModuleFailed || audit.CommandStartFailed != out.CommandStartFailed || audit.Error != out.Error {
				t.Fatalf("audit lost execution outcome: %+v output=%+v", audit, out)
			}
			decoded, err := diagnose.DecodeAdHocResult(raw, "web1")
			if err != nil {
				t.Fatal(err)
			}
			if tc.commandRC != 0 {
				stdout, stderr := "", ""
				if tc.commandRC == 7 {
					stdout, stderr = "out", "err"
				}
				if !out.RCKnown || out.RC != tc.commandRC || out.Outcome != "command_nonzero" || out.Stdout != stdout || out.Stderr != stderr || out.LauncherRCKnown || out.Error != "" {
					t.Fatalf("real command result changed=%+v", out)
				}
				return
			}
			if out.RCKnown || out.RC != 0 || out.Outcome != "unknown" || out.LauncherRC != tc.launcherRC || !out.LauncherRCKnown || out.Error == "" || out.Stdout != "" || out.Stderr != "" {
				t.Fatalf("launcher status mistaken for command exit=%+v", out)
			}
			component := diagnose.BuildComponentOutput("systemd", "", nil, true, []diagnose.StepResult{{Step: diagnose.Step{ID: "runtime-state"}, Result: decoded}})
			if component.RuntimePresent || component.RuntimeRunning || component.Verdict != "insufficient_evidence" {
				t.Fatalf("live module failure became component state=%+v", component)
			}
		})
	}
}

func TestDiagnoseStepAudit_ExecutionFailureErrorIsSanitized(t *testing.T) {
	record := diagnoseAuditRecord{Steps: stepAuditList([]diagnose.StepResult{{Step: diagnose.Step{ID: "wrapper", Command: "/bin/true"}, Result: diagnose.AdHocResult{ModuleFailed: true, LauncherRC: 127, LauncherRCKnown: true, Message: "password=module-audit-secret " + strings.Repeat("界", maxDiagnosticResponseBytes), ModuleStderr: "token=module-stderr-secret"}}})}
	dir := t.TempDir()
	if err := writeDiagnoseAudit(dir, record); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "record.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved diagnoseAuditRecord
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	step := saved.Steps[0]
	if step.RCKnown || !step.ModuleFailed || !step.LauncherRCKnown || step.LauncherRC != 127 || step.Error == "" || len(step.Error) > maxDiagnosticResponseBytes || strings.Contains(string(data), "module-audit-secret") || strings.Contains(string(data), "module-stderr-secret") || !strings.Contains(step.Error, "[REDACTED]") {
		t.Fatalf("unsafe or misleading stage-failure audit=%+v", step)
	}
}
