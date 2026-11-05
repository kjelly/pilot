package evidence

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestControllerVerifyDiagnosticsStrict(t *testing.T) {
	row := verifyRowPrefix + `{"id":"C1","host":"h","status":"pass","exit_code":0,"probe_status":"ok","stdout":"literal"}` + "\n"
	footer := verifyReportPrefix + `{"schema":"pilot-verify-diagnostics/v1","rows":1,"complete":true}` + "\n"
	good := row + footer
	parsed, err := ParseControllerVerifyDiagnostics(good)
	if err != nil || !parsed.Complete || len(parsed.Rows) != 1 {
		t.Fatalf("valid native rows refused: %v %+v", err, parsed)
	}
	for name, output := range map[string]string{
		"missing-footer": row, "missing-rows": footer, "duplicate-footer": good + footer,
		"after-footer": good + row, "false-complete": strings.Replace(good, `"complete":true`, `"complete":false`, 1),
		"wrong-count":       strings.Replace(good, `"rows":1`, `"rows":2`, 1),
		"unknown-row-field": strings.Replace(good, `"stdout":"literal"`, `"unsupported":"literal"`, 1),
		"trailing-json":     strings.Replace(good, `"stdout":"literal"}`, `"stdout":"literal"} {}`, 1),
		"invalid-status":    strings.Replace(good, `"status":"pass"`, `"status":"unknown"`, 1),
		"bounded-export":    strings.Repeat("x", 20*1024*1024+1),
	} {
		t.Run(name, func(t *testing.T) {
			parsed, err := ParseControllerVerifyDiagnostics(output)
			if err == nil || parsed.Complete {
				t.Fatal("incomplete/invalid export accepted as complete")
			}
		})
	}
}

func TestSanitizeVerifierRowProtocol(t *testing.T) {
	for _, secret := range []string{"pass", "v1", "ok"} {
		record := &Record{Verify: []VerifyResult{{DiagnosticsSchema: VerifyDiagnosticsSchema, DiagnosticsComplete: true, Rows: []VerifyRowDiagnostic{{ID: "C1", Status: "pass", ProbeStatus: "ok", Stdout: secret, Stderr: secret, Detail: secret, Message: secret}}}}}
		if err := SanitizeRecord(record, []SecretSource{{Key: "api_token", value: secret}}); err != nil {
			t.Fatal(err)
		}
		row := record.Verify[0].Rows[0]
		if row.Status != "pass" || row.ProbeStatus != "ok" || record.Verify[0].DiagnosticsSchema != VerifyDiagnosticsSchema || row.Stdout != "<redacted>" || row.Detail != "<redacted>" || row.Stderr != "<redacted>" || row.Message != "<redacted>" {
			raw, _ := json.Marshal(record)
			t.Fatalf("row protocol/data sanitation mismatch: %s", raw)
		}
	}
}
