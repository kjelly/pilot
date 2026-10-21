package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/diagnose"
	"github.com/kjelly/pilot/internal/networkcheck"
	"github.com/kjelly/pilot/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func evidenceIdentityRunner(t *testing.T) diagnose.AdHocRunner {
	t.Helper()
	return func(_ context.Context, args []string, _ int) (string, int, error) {
		if args[len(args)-1] != "id -un" {
			t.Errorf("identity command = %q", args[len(args)-1])
		}
		return diagnoseOKDoc(t, args[0], 0, "evidence-operator\n"), 0, nil
	}
}

func TestDiagnoseEvidence_ReconstructsSuccessNonzeroAndUnavailable(t *testing.T) {
	requireRealAnsible(t)
	for _, tc := range []struct {
		name     string
		rc       int
		failure  error
		complete bool
	}{
		{"success", 0, nil, true}, {"nonzero", 7, nil, true}, {"query_transport_failure", 0, errors.New("password=transport-secret"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv := writeDiagnoseFixtureInventory(t)
			runner := func(_ context.Context, args []string, _ int) (string, int, error) {
				return diagnoseDocWithStderr(t, args[0], tc.rc, "observed stdout\npassword=output-secret", "useful stderr\npassword=stderr-secret"), tc.rc, tc.failure
			}
			opts := baseDiagnoseOpts(t, inv, runner)
			opts.IdentityRunner = evidenceIdentityRunner(t)
			_, out, err := diagnoseRunHandler(opts)(context.Background(), nil, diagnoseRunInput{Host: "web1", Command: "printf password=command-secret"})
			if err != nil {
				t.Fatal(err)
			}
			if out.AuditStatus != "persisted" || out.EvidenceID == "" {
				t.Fatalf("audit status = %+v", out.diagnoseAuditStatus)
			}
			rec, data, err := readDiagnoseArtifact(out.AuditDirectory)
			if err != nil {
				t.Fatal(err)
			}
			if !rec.Finalized || (rec.EvidenceCompleteness == "complete") != tc.complete || out.EvidenceCompleteness != rec.EvidenceCompleteness {
				t.Fatalf("completeness = %s: %v", rec.EvidenceCompleteness, rec.IncompleteReasons)
			}
			if len(rec.Steps) != 1 || rec.Steps[0].Host != "web1" || rec.Steps[0].ResolvedAddr != "127.0.0.1" || rec.Steps[0].StartedAt.IsZero() || rec.Steps[0].FinishedAt.Before(rec.Steps[0].StartedAt) {
				t.Fatalf("execution evidence = %+v", rec.Steps)
			}
			if len(rec.Identities) != 1 || rec.Identities[0].ObservedEffectiveUser != "evidence-operator" || rec.Identities[0].Observation != "observed" {
				t.Fatalf("identity = %+v", rec.Identities)
			}
			for _, identity := range rec.Identities {
				if identity.Evidence.StartedAt.Before(rec.Start) || identity.Evidence.FinishedAt.After(rec.Finish) {
					t.Fatal("identity execution falls outside diagnosis interval")
				}
			}
			if rec.Provenance.InventorySHA256 == "" || rec.Provenance.ResolvedInventorySHA256 == "" || rec.Provenance.InventoryCapturedAt.IsZero() {
				t.Fatalf("missing provenance = %+v", rec.Provenance)
			}
			if len(rec.EvidenceReferences) != 2 || rec.Steps[0].EvidenceRef != out.EvidenceReferences[0] {
				t.Fatal("missing diagnosis-to-step references")
			}
			var replay diagnoseRunOutput
			if err := json.Unmarshal(rec.Diagnosis, &replay); err != nil {
				t.Fatal(err)
			}
			if replay.Stdout != out.Stdout || replay.Stderr != out.Stderr || replay.Error != out.Error || replay.Outcome != out.Outcome || replay.RC != out.RC || replay.RCKnown != out.RCKnown || replay.Failed != out.Failed || replay.Unreachable != out.Unreachable {
				t.Fatalf("replay differs: %#v vs %#v", replay, out)
			}
			for _, secret := range []string{"output-secret", "stderr-secret", "command-secret", "transport-secret"} {
				if strings.Contains(string(data), secret) {
					t.Fatalf("persisted secret %q", secret)
				}
			}
			if !rec.Redacted {
				t.Fatal("redaction was not recorded")
			}
			info, _ := os.Stat(filepath.Join(out.AuditDirectory, "record.json"))
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("record mode = %v", info.Mode())
			}
			if err := writeDiagnoseAudit(out.AuditDirectory, rec); err == nil {
				t.Fatal("finalized record was overwritten")
			}
		})
	}
}

func TestDiagnoseEvidence_QueryHTTPFailureRetainsDiagnosis(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseGroupFixtureInventory(t, diagnose.ThanosQueryGroup, []string{"thanos"})
	runner := func(_ context.Context, args []string, _ int) (string, int, error) {
		return diagnoseOKDoc(t, args[0], 0, `{"status":"error","error":"backend unavailable password=query-secret"}`+"\nHTTP_STATUS:503"), 0, nil
	}
	opts := baseDiagnoseOpts(t, inv, runner)
	opts.IdentityRunner = evidenceIdentityRunner(t)
	_, out, err := diagnoseMetricsHandler(opts)(context.Background(), nil, diagnoseMetricsInput{Query: "up"})
	if err != nil {
		t.Fatal(err)
	}
	rec, data, err := readDiagnoseArtifact(out.AuditDirectory)
	if err != nil {
		t.Fatal(err)
	}
	var replay diagnoseMetricsOutput
	if err := json.Unmarshal(rec.Diagnosis, &replay); err != nil {
		t.Fatal(err)
	}
	if out.HTTPStatus != 503 || replay.HTTPStatus != 503 || replay.ResultJSON != out.ResultJSON || !strings.Contains(rec.Steps[0].Stdout, "backend unavailable") || rec.EvidenceCompleteness != "incomplete" || out.AuditStatus != "persisted" {
		t.Fatalf("query replay lost evidence: %#v %#v", rec, replay)
	}
	if strings.Contains(string(data), "query-secret") {
		t.Fatal("query response leaked a secret")
	}
}

func TestDiagnoseEvidence_CapturesEveryActualTargetWithDuplicateStepIDs(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseGroupFixtureInventory(t, "test", []string{"web1", "central"})
	runner := func(_ context.Context, args []string, _ int) (string, int, error) {
		return diagnoseOKDoc(t, args[0], 0, args[0]+" output"), 0, nil
	}
	opts := baseDiagnoseOpts(t, inv, runner)
	opts.IdentityRunner = evidenceIdentityRunner(t)
	type output struct {
		diagnoseAuditStatus
		AuditDirectory string `json:"audit_directory"`
		Verdict        string `json:"verdict"`
	}
	handler := withDiagnoseEvidence(opts, "multihost", func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, output, error) {
		ctx = withDeployAnsibleRuntime(ctx, scopedDiagnoseAnsibleRuntime(opts.AnsibleRuntime))
		if _, err := resolveDiagnoseInventory(ctx, opts); err != nil {
			return nil, output{}, err
		}
		var results []diagnose.StepResult
		for _, host := range []string{"web1", "central"} {
			results = append(results, diagnose.RunSteps(ctx, runner, inv, host, []diagnose.Step{{ID: "same_id", Module: "command", Command: "id"}}, time.Second)...)
		}
		dir, err := prepareDiagnoseAuditDir(opts, "multihost", "targets", time.Now())
		if err != nil {
			return nil, output{}, err
		}
		err = writeDiagnoseAudit(dir, diagnoseAuditRecord{Steps: stepAuditList(results), Host: "web1"})
		return nil, output{AuditDirectory: dir, Verdict: "observed"}, err
	})
	_, out, err := handler(context.Background(), nil, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	rec, _, err := readDiagnoseArtifact(out.AuditDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Steps) != 2 || rec.Steps[0].Host != "web1" || rec.Steps[1].Host != "central" || rec.Steps[0].EvidenceRef == rec.Steps[1].EvidenceRef || len(rec.Identities) != 2 {
		t.Fatalf("actual targets lost: %+v", rec)
	}
}

func TestDiagnoseEvidence_WirePaginationReconstructsEntireSanitizedRecord(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t)
	runner := func(_ context.Context, args []string, _ int) (string, int, error) {
		return diagnoseOKDoc(t, args[0], 0, strings.Repeat("界", 40000)+" password=tail-secret"), 0, nil
	}
	opts := baseDiagnoseOpts(t, inv, runner)
	opts.IdentityRunner = evidenceIdentityRunner(t)
	server := mcp.NewServer(&mcp.Implementation{Name: "evidence-test", Version: "1"}, nil)
	registerDiagnoseRunTool(server, opts)
	session := connectDiagnoseTestServer(t, server)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "pilot_diagnose_run", Arguments: map[string]any{"host": "web1", "command": "id"}})
	if err != nil || result.IsError {
		t.Fatalf("diagnose call: %v, %+v", err, result)
	}
	var out diagnoseRunOutput
	marshalWireEvidence(t, result.StructuredContent, &out)
	if !out.Truncated || out.EvidenceCompleteness != "incomplete" {
		t.Fatalf("truncation completeness = %+v", out.diagnoseAuditStatus)
	}
	var reconstructed []byte
	var digest string
	for offset, pages := 0, 0; ; pages++ {
		if pages > 100 {
			t.Fatal("pagination never completed")
		}
		result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "pilot_diagnose_evidence_get", Arguments: map[string]any{"evidence_id": out.EvidenceID, "offset": offset, "sha256": digest}})
		if err != nil || result.IsError {
			t.Fatalf("get call: %v, %+v", err, result)
		}
		var page diagnoseEvidenceGetOutput
		marshalWireEvidence(t, result.StructuredContent, &page)
		chunk, err := base64.StdEncoding.DecodeString(page.Data)
		if err != nil {
			t.Fatal(err)
		}
		if len(chunk) > maxDiagnosePageBytes || page.Offset != offset || !page.Finalized || page.EvidenceCompleteness != "incomplete" {
			t.Fatalf("invalid page %+v", page)
		}
		reconstructed = append(reconstructed, chunk...)
		digest = page.SHA256
		if page.EOF {
			if pages < 1 {
				t.Fatal("fixture did not require pagination")
			}
			break
		}
		if page.NextOffset <= offset {
			t.Fatal("pagination did not advance")
		}
		offset = page.NextOffset
	}
	disk, err := os.ReadFile(filepath.Join(out.AuditDirectory, "record.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reconstructed, disk) || diagnoseSHA256(reconstructed) != digest {
		t.Fatal("remote pages differ from persisted record")
	}
	if strings.Contains(string(reconstructed), "tail-secret") {
		t.Fatal("remote evidence leaked secret")
	}
	var rec diagnoseAuditRecord
	if err := json.Unmarshal(reconstructed, &rec); err != nil {
		t.Fatal(err)
	}
	if !rec.Truncated || len(rec.Diagnosis) == 0 || len(rec.Steps) != 1 {
		t.Fatal("reconstructed record omitted diagnosis or steps")
	}
}

func marshalWireEvidence(t *testing.T, value any, target any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}

func TestDiagnoseEvidence_GetRejectsPathsSymlinksSpecialFilesAndChangedPages(t *testing.T) {
	opts := diagnoseMCPToolsOptions{AuditDir: t.TempDir()}
	dir, err := prepareDiagnoseAuditDir(opts, "test", "read", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := writeDiagnoseAudit(dir, diagnoseAuditRecord{}); err != nil {
		t.Fatal(err)
	}
	id := filepath.Base(dir)
	handler := diagnoseEvidenceGetHandler(opts)
	for _, in := range []diagnoseEvidenceGetInput{{EvidenceID: "../record"}, {EvidenceID: "/etc/passwd"}, {EvidenceID: id, Offset: -1}, {EvidenceID: id, Limit: maxDiagnosePageBytes + 1}, {EvidenceID: id, Offset: 1 << 30}, {EvidenceID: id, SHA256: "stale"}} {
		result, _, err := handler(context.Background(), nil, in)
		if err != nil || result == nil || !result.IsError {
			t.Fatalf("unsafe input accepted: %+v", in)
		}
	}
	result, page, err := handler(context.Background(), nil, diagnoseEvidenceGetInput{EvidenceID: id})
	if err != nil || result != nil || page.Finalized || page.EvidenceCompleteness != "incomplete" {
		t.Fatalf("preliminary record advertised complete: %+v %v", page, err)
	}
	for _, mode := range []string{"directory_symlink", "record_symlink", "record_fifo"} {
		t.Run(mode, func(t *testing.T) {
			attackID := "attack-" + mode
			attackDir := filepath.Join(opts.AuditDir, "diagnose", attackID)
			if mode == "directory_symlink" {
				if err := os.Symlink(dir, attackDir); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(attackDir, 0o700); err != nil {
					t.Fatal(err)
				}
				if mode == "record_symlink" {
					err = os.Symlink(filepath.Join(dir, "record.json"), filepath.Join(attackDir, "record.json"))
				} else {
					err = syscall.Mkfifo(filepath.Join(attackDir, "record.json"), 0o600)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			result, _, err := handler(context.Background(), nil, diagnoseEvidenceGetInput{EvidenceID: attackID})
			if err != nil || result == nil || !result.IsError {
				t.Fatal("unsafe artifact accepted")
			}
		})
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "record.json" {
		t.Fatalf("read-only retrieval created files: %v", entries)
	}
}

func TestDiagnoseEvidence_FinalWriteFailureIsDistinctFromCompleteness(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t)
	runner := func(_ context.Context, args []string, _ int) (string, int, error) {
		return diagnoseOKDoc(t, args[0], 0, "result"), 0, nil
	}
	opts := baseDiagnoseOpts(t, inv, runner)
	opts.IdentityRunner = func(ctx context.Context, args []string, timeout int) (string, int, error) {
		matches, err := filepath.Glob(filepath.Join(opts.AuditDir, "diagnose", "*"))
		if err != nil || len(matches) != 1 {
			t.Fatalf("audit directory: %v %v", matches, err)
		}
		if err := os.RemoveAll(matches[0]); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(matches[0], []byte("block final write"), 0o600); err != nil {
			t.Fatal(err)
		}
		return evidenceIdentityRunner(t)(ctx, args, timeout)
	}
	_, out, err := diagnoseRunHandler(opts)(context.Background(), nil, diagnoseRunInput{Host: "web1", Command: "id"})
	if err != nil {
		t.Fatal(err)
	}
	if out.AuditStatus != "failed" || out.AuditError == "" || out.EvidenceCompleteness != "complete" {
		t.Fatalf("write status confused with collection completeness: %+v", out.diagnoseAuditStatus)
	}
}

func TestDiagnoseEvidence_ActualLocalExecutionIdentityAndFailureReplay(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t)
	opts := baseDiagnoseOpts(t, inv, nil)
	opts.StepTimeout = 20 * time.Second
	opts.AnsibleRuntime.Env = append(opts.AnsibleRuntime.Env, "ANSIBLE_REMOTE_TEMP="+t.TempDir())
	_, out, err := diagnoseRunHandler(opts)(context.Background(), nil, diagnoseRunInput{Host: "web1", Command: `python3 -c 'import sys; print("observed"); print("stderr proof", file=sys.stderr); sys.exit(3)'`})
	if err != nil {
		t.Fatal(err)
	}
	rec, _, err := readDiagnoseArtifact(out.AuditDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if out.RC != 3 || out.EvidenceCompleteness != "complete" || len(rec.Identities) != 1 || rec.Identities[0].Observation != "observed" || rec.Identities[0].ObservedEffectiveUser == "" || rec.Identities[0].Evidence.Command != "id -un" {
		t.Fatalf("actual identity not observed: %#v %#v", out, rec.Identities)
	}
	var replay diagnoseRunOutput
	if err := json.Unmarshal(rec.Diagnosis, &replay); err != nil {
		t.Fatal(err)
	}
	if replay.RC != 3 || replay.Stdout != "observed" || replay.Stderr != "stderr proof" || rec.Steps[0].Failed != true {
		t.Fatalf("actual command cannot be replayed: %#v", replay)
	}
	if rec.Provenance.ServerRevisionSource != "go_build_info" && rec.Provenance.ServerRevision != "" {
		t.Fatal("server revision mislabeled")
	}
	if rec.Provenance.InventorySHA256 != diagnoseSHA256(mustReadEvidenceFile(t, inv)) {
		t.Fatal("inventory source hash differs")
	}
}

func mustReadEvidenceFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDiagnoseEvidence_MissingExecutionIdentityIsExplicitlyIncomplete(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t)
	opts := baseDiagnoseOpts(t, inv, func(_ context.Context, args []string, _ int) (string, int, error) {
		return diagnoseOKDoc(t, args[0], 0, "result"), 0, nil
	})
	_, out, err := diagnoseRunHandler(opts)(context.Background(), nil, diagnoseRunInput{Host: "web1", Command: "id"})
	if err != nil {
		t.Fatal(err)
	}
	rec, _, err := readDiagnoseArtifact(out.AuditDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if rec.EvidenceCompleteness != "incomplete" || len(rec.Identities) != 1 || rec.Identities[0].Observation != "unknown" || !strings.Contains(fmt.Sprint(rec.IncompleteReasons), "execution_identity_unknown") {
		t.Fatalf("unknown identity reported complete: %+v", rec)
	}
}

func TestDiagnoseEvidence_PostExecutionToolErrorHasRetrievableEvidence(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t)
	opts := baseDiagnoseOpts(t, inv, func(_ context.Context, args []string, _ int) (string, int, error) {
		return diagnoseOKDoc(t, args[0], 0, "query evidence"), 0, nil
	})
	opts.IdentityRunner = evidenceIdentityRunner(t)
	server := mcp.NewServer(&mcp.Implementation{Name: "evidence-test", Version: "1"}, nil)
	handler := withDiagnoseEvidence(opts, "failedquery", func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, diagnoseRunOutput, error) {
		ctx = withDeployAnsibleRuntime(ctx, scopedDiagnoseAnsibleRuntime(opts.AnsibleRuntime))
		if _, err := resolveDiagnoseInventory(ctx, opts); err != nil {
			return nil, diagnoseRunOutput{}, err
		}
		diagnose.RunSteps(ctx, opts.AdHocRunner, inv, "web1", []diagnose.Step{{ID: "query", Module: "command", Command: "query"}}, time.Second)
		return toolErrorResult(mcpToolError{Code: mcpErrInternal, Message: "cannot parse query password=parse-secret"}), diagnoseRunOutput{}, nil
	})
	addRecoveredTool(server, &mcp.Tool{Name: "pilot_diagnose_failed_query"}, handler)
	registerDiagnoseEvidenceTool(server, opts)
	session := connectDiagnoseTestServer(t, server)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "pilot_diagnose_failed_query", Arguments: map[string]any{}})
	if err != nil || !result.IsError || result.StructuredContent != nil {
		t.Fatalf("failed query wire result: %v %+v", err, result)
	}
	var failure mcpToolError
	if err := json.Unmarshal([]byte(result.Content[0].(*mcp.TextContent).Text), &failure); err != nil {
		t.Fatal(err)
	}
	if failure.EvidenceID == "" || failure.AuditStatus != "persisted" || failure.EvidenceCompleteness != "incomplete" || strings.Contains(failure.Message, "parse-secret") {
		t.Fatalf("error has no safe evidence reference: %+v", failure)
	}
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "pilot_diagnose_evidence_get", Arguments: map[string]any{"evidence_id": failure.EvidenceID}})
	if err != nil || result.IsError {
		t.Fatalf("cannot retrieve failed query evidence: %v %+v", err, result)
	}
	var page diagnoseEvidenceGetOutput
	marshalWireEvidence(t, result.StructuredContent, &page)
	data, err := base64.StdEncoding.DecodeString(page.Data)
	if err != nil {
		t.Fatal(err)
	}
	var rec diagnoseAuditRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Verdict != "tool_error" || len(rec.Steps) != 1 || rec.Steps[0].Stdout != "query evidence" || !strings.Contains(string(rec.Diagnosis), "cannot parse query") || strings.Contains(string(data), "parse-secret") {
		t.Fatal("failed query cannot be reconstructed")
	}
}

func TestDiagnoseEvidence_IdentityTruncationMarksRecordAndResponseIncomplete(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t)
	opts := baseDiagnoseOpts(t, inv, func(_ context.Context, args []string, _ int) (string, int, error) {
		return diagnoseOKDoc(t, args[0], 0, "observed"), 0, nil
	})
	opts.IdentityRunner = func(_ context.Context, args []string, _ int) (string, int, error) {
		return diagnoseDocWithStderr(t, args[0], 0, "root", strings.Repeat("x", maxDiagnosticResponseBytes+100)+" password=identity-secret"), 0, nil
	}
	_, out, err := diagnoseRunHandler(opts)(context.Background(), nil, diagnoseRunInput{Host: "web1", Command: "id"})
	if err != nil {
		t.Fatal(err)
	}
	rec, data, err := readDiagnoseArtifact(out.AuditDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if rec.EvidenceCompleteness != "incomplete" || !rec.Truncated || !out.Truncated || !rec.Redacted || !out.Redacted || out.EvidenceCompleteness != rec.EvidenceCompleteness {
		t.Fatalf("identity safety flags diverged: %+v %+v", rec, out.diagnoseAuditStatus)
	}
	if rec.Identities[0].ObservedEffectiveUser != "root" || strings.Contains(string(data), "identity-secret") {
		t.Fatal("identity observation or redaction lost")
	}
}

func writeEvidenceSNMPWorkspace(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	writeMonitoringTargetFixtureWorkspace(t, root)
	for _, dir := range []string{"contracts", "playbooks", "monitoring/snmp/generated"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	contractData := mustReadEvidenceFile(t, filepath.Join(repoRootForTest(t), "contracts/snmp-exporter.yaml"))
	files := map[string]string{
		"contracts/snmp-exporter.yaml":         string(contractData),
		"playbooks/site.yml":                   "- import_playbook: apply/snmp-exporter-apply.yml\n",
		"monitoring/snmp/generated/if_mib.yml": "modules: {}\n",
		"monitoring/snmp/catalog.yml":          "schemaVersion: 1\nmodules:\n  if_mib: {file: generated/if_mib.yml}\nauthProfiles:\n  lab-v3: {version: 3, securityLevel: authPriv, authProtocol: SHA256, privProtocol: AES, credentialRef: lab-v3}\n",
		"inventory.yml":                        "all:\n  children:\n    snmp-exporter:\n      hosts:\n        exporter: {ansible_host: 127.0.0.2, ansible_connection: local, ansible_user: exporter-user}\n    prometheus:\n      hosts:\n        prometheus: {ansible_host: 127.0.0.3, ansible_connection: local, ansible_user: metrics-user}\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PILOT_ROOT", root)
	return root, filepath.Join(root, "inventory.yml")
}

func TestDiagnoseEvidence_RealPipelineHandlerCapturesInventoryAndEveryProbe(t *testing.T) {
	requireRealAnsible(t)
	root, inv := writeEvidenceSNMPWorkspace(t)
	previous := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = previous })
	st, err := openSpecStore()
	if err != nil {
		t.Fatal(err)
	}
	writer, err := store.StartRun(context.Background(), st, store.RunStarted{RunID: "snmp-evidence-run", Component: "snmp-exporter", Hosts: []string{"exporter"}, Inventory: inv})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Finish(context.Background(), store.RunFinished{Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	runner := func(_ context.Context, args []string, _ int) (string, int, error) {
		return diagnoseOKDoc(t, args[0], 0, "running"), 0, nil
	}
	opts := baseDiagnoseOpts(t, inv, runner)
	opts.WorkspaceDir = root
	opts.IdentityRunner = evidenceIdentityRunner(t)
	result, out, err := diagnoseMonitoringPipelineHandler(opts)(context.Background(), nil, monitoringPipelineInput{Target: "core-sw-01"})
	if err != nil || result != nil {
		t.Fatalf("pipeline result %v %+v", err, result)
	}
	rec, _, err := readDiagnoseArtifact(filepath.Join(opts.AuditDir, "diagnose", out.EvidenceID))
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Steps) < 2 || rec.Provenance.InventorySHA256 == "" || rec.Provenance.ResolvedInventorySHA256 == "" || rec.Provenance.ServerExecutableSHA256 == "" {
		t.Fatalf("pipeline provenance or actual probes missing: verdict=%s steps=%d provenance=%+v", out.Verdict, len(rec.Steps), rec.Provenance)
	}
	hosts := map[string]bool{}
	for _, step := range rec.Steps {
		hosts[step.Host] = true
		if step.ResolvedAddr == step.Host || step.StartedAt.IsZero() {
			t.Fatal("pipeline probe execution provenance missing")
		}
	}
	if !hosts["exporter"] || !hosts["prometheus"] || len(rec.Identities) != 2 {
		t.Fatalf("pipeline lost actual targets: %v", hosts)
	}
	if rec.Identities[0].ConfiguredRemoteUser == "" || rec.EvidenceCompleteness != "incomplete" || out.AuditStatus != "persisted" {
		t.Fatalf("pipeline metadata missing: %+v", rec)
	}
	var replay monitoringPipelineOutput
	if err := json.Unmarshal(rec.Diagnosis, &replay); err != nil {
		t.Fatal(err)
	}
	if replay.Verdict != out.Verdict || !reflect.DeepEqual(replay.Stages, out.Stages) {
		t.Fatal("pipeline conclusion cannot be reconstructed")
	}
}

func TestDiagnoseEvidence_SNMPProbeRecordsExporterExecution(t *testing.T) {
	requireRealAnsible(t)
	root, inv := writeEvidenceSNMPWorkspace(t)
	runner := func(_ context.Context, args []string, _ int) (string, int, error) {
		return diagnoseOKDoc(t, args[0], 0, "sysUpTime 100\nHTTP_STATUS:200"), 0, nil
	}
	opts := baseDiagnoseOpts(t, inv, runner)
	opts.WorkspaceDir = root
	opts.IdentityRunner = evidenceIdentityRunner(t)
	result, out, err := diagnoseSNMPProbeHandler(opts)(context.Background(), nil, diagnoseSNMPProbeInput{Target: "core-sw-01"})
	if err != nil || result != nil {
		t.Fatalf("probe error: %v %+v", err, result)
	}
	rec, _, err := readDiagnoseArtifact(out.AuditDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != "healthy" || len(rec.Steps) != 1 || rec.Steps[0].Host != "exporter" || rec.Steps[0].ResolvedAddr != "127.0.0.2" || rec.Host != "core-sw-01" {
		t.Fatalf("SNMP subject confused with actual exporter: verdict=%s workspace=%+v transport=%s %+v", out.Verdict, out.Workspace, out.Transport, rec.Steps)
	}
	if rec.EvidenceCompleteness != "complete" || out.EvidenceCompleteness != "complete" {
		t.Fatalf("SNMP evidence incomplete: %v", rec.IncompleteReasons)
	}
}

func TestDiagnoseEvidence_GetRejectsUnknownDuplicateAndUnsanitizedFields(t *testing.T) {
	opts := diagnoseMCPToolsOptions{AuditDir: t.TempDir()}
	for _, extra := range []string{`,"password":"stored-secret"`, `,"inventory":"password=stored-secret","inventory":"safe"`, `,"diagnosis":{"password":"stored-secret"}`} {
		dir, err := prepareDiagnoseAuditDir(opts, "policy", fmt.Sprintf("case%d", len(extra)), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := writeDiagnoseAudit(dir, diagnoseAuditRecord{}); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "record.json")
		data := mustReadEvidenceFile(t, path)
		tampered := strings.TrimSuffix(string(data), "}\n") + extra + "}\n"
		if !json.Valid([]byte(tampered)) {
			t.Fatal("invalid tampering fixture")
		}
		if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
			t.Fatal(err)
		}
		result, _, err := diagnoseEvidenceGetHandler(opts)(context.Background(), nil, diagnoseEvidenceGetInput{EvidenceID: filepath.Base(dir)})
		if err != nil || result == nil || !result.IsError {
			t.Fatal("unsanitized stored bytes were exposed")
		}
		encoded, _ := json.Marshal(result)
		if strings.Contains(string(encoded), "stored-secret") {
			t.Fatal("policy rejection leaked stored secret")
		}
	}
}

func TestDiagnoseEvidence_ServerHashTracksExecutingInodeAfterReplacement(t *testing.T) {
	if os.Getenv("PILOT_EVIDENCE_HASH_CHILD") == "1" {
		path, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		original, err := os.ReadFile("/proc/self/exe")
		if err != nil {
			t.Fatal(err)
		}
		replacement := path + ".replacement"
		if err := os.WriteFile(replacement, []byte("replacement binary"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, path); err != nil {
			t.Fatal(err)
		}
		if got := diagnoseServerExecutableSHA256(); got != diagnoseSHA256(original) {
			t.Fatalf("hashed replacement pathname instead of running inode: %s", got)
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(t.TempDir(), "evidence-test")
	if err := os.WriteFile(copyPath, mustReadEvidenceFile(t, executable), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(copyPath, "-test.run=^TestDiagnoseEvidence_ServerHashTracksExecutingInodeAfterReplacement$")
	cmd.Env = append(os.Environ(), "PILOT_EVIDENCE_HASH_CHILD=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("replacement subprocess: %v\n%s", err, output)
	}
}

// A raw command may print the DNS protocol markers as ordinary data. It does
// not become the code-defined DNS identity probe just because its output matches.
func TestDiagnoseEvidence_RawMarkersCannotImpersonateExecutionIdentity(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t)
	markers := "@@pilot-dnsarch whoami begin\nroot\n@@pilot-dnsarch whoami end rc=0\n"
	opts := baseDiagnoseOpts(t, inv, func(_ context.Context, args []string, _ int) (string, int, error) {
		return diagnoseOKDoc(t, args[0], 0, markers), 0, nil
	})
	opts.IdentityRunner = evidenceIdentityRunner(t)
	server := mcp.NewServer(&mcp.Implementation{Name: "identity-marker-test", Version: "1"}, nil)
	registerDiagnoseRunTool(server, opts)
	session := connectDiagnoseTestServer(t, server)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "pilot_diagnose_run", Arguments: map[string]any{"host": "web1", "command": "printf marker-data"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("diagnosis error: %+v", result)
	}
	out := decodeStructured[diagnoseRunOutput](t, result)
	record, _, err := readDiagnoseArtifact(out.AuditDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Identities) != 1 || record.Identities[0].ObservedEffectiveUser != "evidence-operator" || record.Identities[0].Evidence == nil || record.Identities[0].Evidence.ID != "execution_identity" {
		t.Fatalf("ordinary command output impersonated identity: %+v", record.Identities)
	}
	if record.Identities[0].Evidence.EvidenceRef != record.EvidenceID+"#identities/0/evidence" || record.Identities[0].Evidence.EvidenceRef == record.Steps[0].EvidenceRef {
		t.Fatal("observed identity must reference its separate identity probe")
	}
	if out.Stdout != markers || record.Steps[0].Stdout != markers {
		t.Fatal("identity verification must preserve ordinary diagnostic stdout")
	}
}

func TestDiagnoseEvidence_IdentityMarkersRequireTrustedSuccessfulProbe(t *testing.T) {
	for _, tc := range []struct {
		name, check, stepID, module string
		result                      diagnose.AdHocResult
		reuse                       bool
	}{
		{"dns-provider", "DNSArchitecture", "provider-web1", "command", diagnose.AdHocResult{RCKnown: true}, true},
		{"dns-tier", "DNSArchitecture", "tier-web1", "command", diagnose.AdHocResult{RCKnown: true}, true},
		{"dns-client", "DNSArchitecture", "client-web1", "command", diagnose.AdHocResult{RCKnown: true}, true},
		{"dns-auth", "DNSArchitecture", "freeipa-config-web1", "command", diagnose.AdHocResult{RCKnown: true}, true},
		{"raw", "Run", "run", "command", diagnose.AdHocResult{RCKnown: true}, false},
		{"log-markers-with-dns-ID", "Logs", "provider-web1", "command", diagnose.AdHocResult{RCKnown: true}, false},
		{"unrecognized-dns-step", "DNSArchitecture", "logs", "command", diagnose.AdHocResult{RCKnown: true}, false},
		{"other-host", "DNSArchitecture", "provider-web2", "command", diagnose.AdHocResult{RCKnown: true}, false},
		{"other-module", "DNSArchitecture", "provider-web1", "shell", diagnose.AdHocResult{RCKnown: true}, false},
		{"failed", "DNSArchitecture", "provider-web1", "command", diagnose.AdHocResult{RCKnown: true, RC: 7, Failed: true}, false},
		{"unknown", "DNSArchitecture", "provider-web1", "command", diagnose.AdHocResult{}, false},
		{"module-failed", "DNSArchitecture", "provider-web1", "command", diagnose.AdHocResult{ModuleFailed: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.result.Stdout = "@@pilot-dnsarch whoami begin\nroot\n@@pilot-dnsarch whoami end rc=0\n"
			steps := stepAuditList([]diagnose.StepResult{{Step: diagnose.Step{ID: tc.stepID, Module: tc.module}, Host: "web1", Result: tc.result}})
			calls := 0
			opts := diagnoseMCPToolsOptions{StepTimeout: time.Second, IdentityRunner: func(ctx context.Context, args []string, timeout int) (string, int, error) {
				calls++
				return evidenceIdentityRunner(t)(ctx, args, timeout)
			}}
			identities := collectDiagnoseIdentities(context.Background(), opts, networkcheck.ResolvedInventory{}, steps, tc.check)
			wantUser, wantID, wantCalls := "evidence-operator", "execution_identity", 1
			if tc.reuse {
				wantUser, wantID, wantCalls = "root", tc.stepID, 0
			}
			if len(identities) != 1 || identities[0].ObservedEffectiveUser != wantUser || identities[0].Evidence == nil || identities[0].Evidence.ID != wantID || calls != wantCalls {
				t.Fatalf("identity source was not trusted: calls=%d identities=%+v", calls, identities)
			}
		})
	}
}
