package detection

import (
	"encoding/json"
	"os"
	"testing"
)

// TestModelSchema_EmbeddedCopyMatchesMonitoringTarget locks the two
// canonical schema files and the prompt file to their go:embed-able copies
// under internal/detection/{schemas,prompts} — go:embed cannot use ".."
// to reach monitoring/detection/ directly (see model_schema.go/model_prompt.go).
func TestModelSchema_EmbeddedCopyMatchesMonitoringTarget(t *testing.T) {
	cases := []struct {
		embedded []byte
		target   string
	}{
		{modelBatchRequestSchemaJSON, "../../monitoring/detection/schemas/model-detection-batch-request-v1.json"},
		{modelBatchResponseSchemaJSON, "../../monitoring/detection/schemas/model-detection-batch-response-v1.json"},
	}
	for _, c := range cases {
		want, err := os.ReadFile(c.target)
		if err != nil {
			t.Fatalf("read %s: %v", c.target, err)
		}
		if string(want) != string(c.embedded) {
			t.Errorf("%s diverges from its embedded internal/detection/schemas copy", c.target)
		}
	}

	wantPrompt, err := os.ReadFile("../../monitoring/detection/model-prompts/host-anomaly-v1.txt")
	if err != nil {
		t.Fatalf("read prompt target: %v", err)
	}
	if string(wantPrompt) != hostAnomalyPromptV1 {
		t.Error("monitoring/detection/model-prompts/host-anomaly-v1.txt diverges from its embedded internal/detection/prompts copy")
	}

	wantFLMPrompt, err := os.ReadFile("../../monitoring/detection/model-prompts/host-anomaly-flm-v1.txt")
	if err != nil {
		t.Fatalf("read flm prompt target: %v", err)
	}
	if string(wantFLMPrompt) != hostAnomalyFLMPromptV1 {
		t.Error("monitoring/detection/model-prompts/host-anomaly-flm-v1.txt diverges from its embedded internal/detection/prompts copy")
	}
}

func validRequest() ModelBatchRequest {
	return ModelBatchRequest{
		SchemaVersion: 1,
		RequestID:     "req-1",
		PromptVersion: 1,
		WindowSeconds: 600,
		Candidates: []ModelCandidateRequest{
			{CandidateID: "host-a", PilotHost: "host-a", Site: "site-1", EvaluationTime: 1000, Current: map[string]float64{"cpu": 0.9}},
			{CandidateID: "host-b", PilotHost: "host-b", Site: "site-1", EvaluationTime: 1000, Current: map[string]float64{"cpu": 0.5}},
		},
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestModelBatch_AllCandidatesHaveUniqueCandidateID (spec §29/§48).
func TestModelBatch_AllCandidatesHaveUniqueCandidateID(t *testing.T) {
	req := validRequest()
	req.Candidates[1].CandidateID = req.Candidates[0].CandidateID // duplicate
	if err := ValidateBatchRequest(mustMarshal(t, req)); err == nil {
		t.Fatal("expected error for duplicate candidate_id, got nil")
	}
}

// TestModelBatch_ResponseSetMustExactlyMatchRequestSet (spec §30/§48):
// both directions — a missing candidate and an extra/unknown candidate
// both invalidate the whole batch.
func TestModelBatch_ResponseSetMustExactlyMatchRequestSet(t *testing.T) {
	req := validRequest()

	missing := ModelBatchResponse{
		SchemaVersion: 1, RequestID: req.RequestID, Status: "ok",
		Candidates: []ModelCandidateResponse{
			{CandidateID: "host-a", Score: 0.5, Confidence: 0.5, CategoryHint: "x", Contributors: []ModelContributor{}},
		},
	}
	if _, err := ValidateBatchResponse(mustMarshal(t, missing), req); err == nil {
		t.Error("expected error when response omits a request candidate_id")
	}

	extra := ModelBatchResponse{
		SchemaVersion: 1, RequestID: req.RequestID, Status: "ok",
		Candidates: []ModelCandidateResponse{
			{CandidateID: "host-a", Score: 0.5, Confidence: 0.5, CategoryHint: "x", Contributors: []ModelContributor{}},
			{CandidateID: "host-b", Score: 0.5, Confidence: 0.5, CategoryHint: "x", Contributors: []ModelContributor{}},
			{CandidateID: "host-c", Score: 0.5, Confidence: 0.5, CategoryHint: "x", Contributors: []ModelContributor{}},
		},
	}
	if _, err := ValidateBatchResponse(mustMarshal(t, extra), req); err == nil {
		t.Error("expected error when response has a candidate_id not in the request")
	}
}

// TestModelBatch_UnknownContributorInvalidatesBatch (spec §19/§30/§48).
func TestModelBatch_UnknownContributorInvalidatesBatch(t *testing.T) {
	req := validRequest()
	resp := ModelBatchResponse{
		SchemaVersion: 1, RequestID: req.RequestID, Status: "ok",
		Candidates: []ModelCandidateResponse{
			{CandidateID: "host-a", Score: 0.5, Confidence: 0.5, CategoryHint: "x", Contributors: []ModelContributor{{Feature: "not_in_current", Score: 0.5}}},
			{CandidateID: "host-b", Score: 0.5, Confidence: 0.5, CategoryHint: "x", Contributors: []ModelContributor{}},
		},
	}
	if _, err := ValidateBatchResponse(mustMarshal(t, resp), req); err == nil {
		t.Fatal("expected error for a contributor feature absent from the candidate's current")
	}
}

func TestValidateBatchResponse_InsufficientDataRequiresZeroedShape(t *testing.T) {
	req := validRequest()
	bad := ModelBatchResponse{
		SchemaVersion: 1, RequestID: req.RequestID, Status: "insufficient_data",
		Candidates: []ModelCandidateResponse{
			{CandidateID: "host-a", Score: 0.4, Confidence: 0, CategoryHint: "", Contributors: []ModelContributor{}},
			{CandidateID: "host-b", Score: 0, Confidence: 0, CategoryHint: "", Contributors: []ModelContributor{}},
		},
	}
	if _, err := ValidateBatchResponse(mustMarshal(t, bad), req); err == nil {
		t.Fatal("expected error for insufficient_data candidate with nonzero score")
	}

	good := bad
	good.Candidates[0].Score = 0
	if _, err := ValidateBatchResponse(mustMarshal(t, good), req); err != nil {
		t.Fatalf("expected zeroed insufficient_data batch to validate, got %v", err)
	}
}

func TestValidateBatchResponse_RequestIDMismatchInvalidatesBatch(t *testing.T) {
	req := validRequest()
	resp := ModelBatchResponse{
		SchemaVersion: 1, RequestID: "different-id", Status: "ok",
		Candidates: []ModelCandidateResponse{
			{CandidateID: "host-a", Score: 0.5, Confidence: 0.5, CategoryHint: "x", Contributors: []ModelContributor{}},
			{CandidateID: "host-b", Score: 0.5, Confidence: 0.5, CategoryHint: "x", Contributors: []ModelContributor{}},
		},
	}
	if _, err := ValidateBatchResponse(mustMarshal(t, resp), req); err == nil {
		t.Fatal("expected error for request_id mismatch")
	}
}

func TestValidateBatchResponse_NonFiniteScoreRejected(t *testing.T) {
	req := validRequest()
	raw := []byte(`{"schema_version":1,"request_id":"req-1","status":"ok","candidates":[
		{"candidate_id":"host-a","score":NaN,"confidence":0.5,"category_hint":"x","contributors":[]},
		{"candidate_id":"host-b","score":0.5,"confidence":0.5,"category_hint":"x","contributors":[]}
	]}`)
	if _, err := ValidateBatchResponse(raw, req); err == nil {
		t.Fatal("expected error for a NaN score")
	}
}

func TestValidateBatchRequest_AdditionalPropertiesRejected(t *testing.T) {
	raw := []byte(`{"schema_version":1,"request_id":"r","prompt_version":1,"window_seconds":600,"candidates":[
		{"candidate_id":"a","pilot_host":"a","site":"s","evaluation_time":1,"current":{},"unexpected_field":true}
	]}`)
	if err := ValidateBatchRequest(raw); err == nil {
		t.Fatal("expected error for an unknown candidate field (additionalProperties: false)")
	}
}
