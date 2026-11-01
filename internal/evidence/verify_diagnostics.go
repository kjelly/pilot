package evidence

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const VerifyDiagnosticsSchema = "pilot-verify-diagnostics/v1"
const verifyRowPrefix = "PILOT_CONTROLLER_VERIFY_ROW "
const verifyReportPrefix = "PILOT_CONTROLLER_VERIFY_REPORT "

// VerifyRowDiagnostic retains the native verifier row after metadata sanitation.
// stdout/stderr and mismatch detail remain data; only validated protocol enums
// are exempt from known-secret substitution.
type VerifyRowDiagnostic struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	Detail        string `json:"detail"`
	Host          string `json:"host,omitempty"`
	ExitCode      int    `json:"exit_code"`
	ProbeStatus   string `json:"probe_status,omitempty"`
	Stdout        string `json:"stdout,omitempty"`
	Stderr        string `json:"stderr,omitempty"`
	Message       string `json:"message,omitempty"`
	CleanupStatus string `json:"cleanup_status,omitempty"`
	CleanupDetail string `json:"cleanup_detail,omitempty"`
}

type VerifyDiagnostics struct {
	Schema   string
	Complete bool
	Rows     []VerifyRowDiagnostic
}

func (v VerifyDiagnostics) Counts() (pass, fail, skip int) {
	for _, row := range v.Rows {
		switch row.Status {
		case "pass":
			pass++
		case "fail":
			fail++
		case "skip", "not_applicable":
			skip++
		}
	}
	return
}

// ParseControllerVerifyDiagnostics recognizes only compact, complete native
// export frames. Other stderr remains captured for redaction and diagnostics.
func ParseControllerVerifyDiagnostics(output string) (VerifyDiagnostics, error) {
	var result VerifyDiagnostics
	refusal := func() (VerifyDiagnostics, error) {
		result.Complete = false
		return result, fmt.Errorf("controlled verifier diagnostic export invalid or incomplete")
	}
	if len(output) > 20*1024*1024 {
		return refusal()
	}
	reports := 0
	var footer struct {
		Schema   string `json:"schema"`
		Rows     int    `json:"rows"`
		Complete bool   `json:"complete"`
	}
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, verifyRowPrefix) {
			if reports != 0 || len(result.Rows) >= 10000 {
				return refusal()
			}
			var row VerifyRowDiagnostic
			decoder := json.NewDecoder(strings.NewReader(strings.TrimPrefix(line, verifyRowPrefix)))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&row) != nil || decoder.Decode(new(any)) != io.EOF || row.ID == "" || (row.Status != "pass" && row.Status != "fail" && row.Status != "skip" && row.Status != "not_applicable") {
				return refusal()
			}
			result.Rows = append(result.Rows, row)
		} else if strings.HasPrefix(line, verifyReportPrefix) {
			reports++
			decoder := json.NewDecoder(strings.NewReader(strings.TrimPrefix(line, verifyReportPrefix)))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&footer) != nil || decoder.Decode(new(any)) != io.EOF {
				return refusal()
			}
		}
	}
	if reports != 1 || footer.Schema != VerifyDiagnosticsSchema || !footer.Complete || footer.Rows != len(result.Rows) || len(result.Rows) == 0 {
		return refusal()
	}
	result.Schema = footer.Schema
	result.Complete = true
	return result, nil
}
