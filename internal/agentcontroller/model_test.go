package agentcontroller

import "testing"

func TestDiagnosisResult_Validate(t *testing.T) {
	cases := []struct {
		name    string
		result  DiagnosisResult
		wantErr bool
	}{
		{"valid explained", DiagnosisResult{Verdict: VerdictExplained, Confidence: 0.9, Evidence: []DiagnosisEvidence{{Tool: "t", Summary: "s"}}}, false},
		{"valid agent_error with no evidence", DiagnosisResult{Verdict: VerdictAgentError, Confidence: 0}, false},
		{"invalid verdict", DiagnosisResult{Verdict: "not_a_real_verdict", Confidence: 0.5, Evidence: []DiagnosisEvidence{{Tool: "t", Summary: "s"}}}, true},
		{"confidence too high", DiagnosisResult{Verdict: VerdictProbable, Confidence: 1.5, Evidence: []DiagnosisEvidence{{Tool: "t", Summary: "s"}}}, true},
		{"confidence negative", DiagnosisResult{Verdict: VerdictProbable, Confidence: -0.1, Evidence: []DiagnosisEvidence{{Tool: "t", Summary: "s"}}}, true},
		{"explained with no evidence", DiagnosisResult{Verdict: VerdictExplained, Confidence: 0.9}, true},
		{"evidence missing tool name", DiagnosisResult{Verdict: VerdictProbable, Confidence: 0.5, Evidence: []DiagnosisEvidence{{Summary: "s"}}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.result.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestNewIncidentEnvelopeV1_AlwaysZeroMutation(t *testing.T) {
	ev := IncidentEvent{Source: "prometheus-rule", Status: "firing", AlertName: "X", Host: "web-1"}
	envelope := NewIncidentEnvelopeV1("inc-1", ev)
	if envelope.SchemaVersion != 1 {
		t.Errorf("schema_version = %d, want 1", envelope.SchemaVersion)
	}
	if envelope.DiagnosticPolicy.MutationAllowed || envelope.DiagnosticPolicy.RawCommandAllowed || envelope.DiagnosticPolicy.WorkspaceWriteAllowed {
		t.Errorf("diagnostic_policy = %+v, want all false", envelope.DiagnosticPolicy)
	}
}

func TestNewIncidentEnvelopeV2_CarriesSubjectAndStaysZeroMutation(t *testing.T) {
	ev := IncidentEvent{
		Source: "prometheus-rule", Status: "firing", AlertName: "SNMPTargetDown",
		Severity: "critical", Component: "snmp", Category: "network_error",
		Subject: IncidentSubject{ID: "core-sw-01", Kind: "network_device", Site: "hq", Managed: false},
	}
	envelope := NewIncidentEnvelopeV2("inc-1", ev)
	if envelope.SchemaVersion != 2 {
		t.Errorf("schema_version = %d, want 2", envelope.SchemaVersion)
	}
	if envelope.Subject != ev.Subject {
		t.Errorf("subject = %+v, want %+v", envelope.Subject, ev.Subject)
	}
	if envelope.Subject.Managed {
		t.Error("external subject must never be Managed=true")
	}
	p := envelope.DiagnosticPolicy
	if p.MutationAllowed || p.RawCommandAllowed || p.WorkspaceWriteAllowed || p.ExternalSubjectMutationAllowed {
		t.Errorf("diagnostic_policy = %+v, want all false", p)
	}
}
