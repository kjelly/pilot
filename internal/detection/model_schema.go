package detection

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"math"

	"github.com/google/jsonschema-go/jsonschema"
)

// The embedded copies below are the Go-embeddable canonical rendering of
// spec Appendix B. monitoring/detection/schemas/*.json (the repo's
// operator-facing target path) must stay byte-identical — locked by
// TestModelSchema_EmbeddedCopyMatchesMonitoringTarget in
// model_schema_test.go — because go:embed patterns cannot use ".." to
// reach outside internal/detection.
//
//go:embed schemas/model-detection-batch-request-v1.json
var modelBatchRequestSchemaJSON []byte

//go:embed schemas/model-detection-batch-response-v1.json
var modelBatchResponseSchemaJSON []byte

var (
	modelBatchRequestSchema  *jsonschema.Resolved
	modelBatchResponseSchema *jsonschema.Resolved
)

func init() {
	modelBatchRequestSchema = mustResolveSchema(modelBatchRequestSchemaJSON)
	modelBatchResponseSchema = mustResolveSchema(modelBatchResponseSchemaJSON)
}

func mustResolveSchema(raw []byte) *jsonschema.Resolved {
	var s jsonschema.Schema
	if err := json.Unmarshal(raw, &s); err != nil {
		panic(fmt.Sprintf("detection: parse embedded schema: %v", err))
	}
	resolved, err := s.Resolve(nil)
	if err != nil {
		panic(fmt.Sprintf("detection: resolve embedded schema: %v", err))
	}
	return resolved
}

// ModelBatchRequest is the wire shape of a Model Detection Batch Request
// (spec §29 / Appendix B). schema_version/window_seconds/prompt_version
// are fixed by the current prompt contract (spec §36).
type ModelBatchRequest struct {
	SchemaVersion int                     `json:"schema_version"`
	RequestID     string                  `json:"request_id"`
	PromptVersion int                     `json:"prompt_version"`
	WindowSeconds int                     `json:"window_seconds"`
	Candidates    []ModelCandidateRequest `json:"candidates"`
}

type ModelCandidateRequest struct {
	CandidateID    string             `json:"candidate_id"`
	PilotHost      string             `json:"pilot_host"`
	Site           string             `json:"site"`
	EvaluationTime int64              `json:"evaluation_time"`
	Current        map[string]float64 `json:"current"`
}

// ModelBatchResponse is the wire shape of a Model Detection Batch Response
// (spec §30 / Appendix B).
type ModelBatchResponse struct {
	SchemaVersion int                      `json:"schema_version"`
	RequestID     string                   `json:"request_id"`
	Status        string                   `json:"status"` // "ok" | "insufficient_data"
	Candidates    []ModelCandidateResponse `json:"candidates"`
}

type ModelCandidateResponse struct {
	CandidateID  string             `json:"candidate_id"`
	Score        float64            `json:"score"`
	Confidence   float64            `json:"confidence"`
	CategoryHint string             `json:"category_hint"`
	Contributors []ModelContributor `json:"contributors"`
}

type ModelContributor struct {
	Feature string  `json:"feature"`
	Score   float64 `json:"score"`
}

// ErrSchemaSemanticMismatch is returned by ValidateBatchResponse for any
// JSON-Schema or semantic-validation failure (spec §30: "任一失敗：discard
// whole batch, all candidates fallback local, error=schema_semantic_mismatch").
var ErrSchemaSemanticMismatch = fmt.Errorf("schema_semantic_mismatch")

// jsonRoundTrip decodes raw JSON bytes into an any-tree (map[string]any /
// []any / float64 / string / bool / nil) suitable for jsonschema.Resolved.Validate,
// and additionally rejects non-finite numbers (JSON Schema's "number" type
// has no portable finite/NaN/Inf keyword — spec §61 requires the
// implementation reject them itself).
func jsonRoundTrip(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if err := rejectNonFiniteNumbers(v); err != nil {
		return nil, err
	}
	return normalizeNumbers(v), nil
}

func rejectNonFiniteNumbers(v any) error {
	switch t := v.(type) {
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			return err
		}
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return fmt.Errorf("non-finite number %q", t.String())
		}
	case map[string]any:
		for _, vv := range t {
			if err := rejectNonFiniteNumbers(vv); err != nil {
				return err
			}
		}
	case []any:
		for _, vv := range t {
			if err := rejectNonFiniteNumbers(vv); err != nil {
				return err
			}
		}
	}
	return nil
}

// normalizeNumbers converts json.Number leaves to float64 so the tree
// matches what jsonschema.Resolved.Validate expects from a plain
// json.Unmarshal into `any`.
func normalizeNumbers(v any) any {
	switch t := v.(type) {
	case json.Number:
		f, _ := t.Float64()
		return f
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			out[k] = normalizeNumbers(vv)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, vv := range t {
			out[i] = normalizeNumbers(vv)
		}
		return out
	default:
		return t
	}
}

// ValidateBatchRequest JSON-Schema validates raw against the request
// schema (spec §29 / Appendix B). It does not perform semantic checks —
// the caller builds the request from trusted internal data, so structural
// validity is the only concern (mirrors the response path's validator for
// symmetry and to guard the request-building code itself in tests).
func ValidateBatchRequest(raw []byte) error {
	v, err := jsonRoundTrip(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSchemaSemanticMismatch, err)
	}
	if err := modelBatchRequestSchema.Validate(v); err != nil {
		return fmt.Errorf("%w: %v", ErrSchemaSemanticMismatch, err)
	}
	return validateRequestSemantics(v)
}

func validateRequestSemantics(v any) error {
	obj, _ := v.(map[string]any)
	candidates, _ := obj["candidates"].([]any)
	seen := map[string]bool{}
	for _, c := range candidates {
		cm, _ := c.(map[string]any)
		id, _ := cm["candidate_id"].(string)
		if seen[id] {
			return fmt.Errorf("%w: duplicate candidate_id %q", ErrSchemaSemanticMismatch, id)
		}
		seen[id] = true
	}
	return nil
}

// ValidateBatchResponse JSON-Schema validates raw against the response
// schema, then applies spec §30's semantic rules against the matching
// request. Any failure is ErrSchemaSemanticMismatch — the whole batch is
// discarded on any mismatch (no partial batch acceptance).
func ValidateBatchResponse(raw []byte, req ModelBatchRequest) (ModelBatchResponse, error) {
	v, err := jsonRoundTrip(raw)
	if err != nil {
		return ModelBatchResponse{}, fmt.Errorf("%w: %v", ErrSchemaSemanticMismatch, err)
	}
	if err := modelBatchResponseSchema.Validate(v); err != nil {
		return ModelBatchResponse{}, fmt.Errorf("%w: %v", ErrSchemaSemanticMismatch, err)
	}
	var resp ModelBatchResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return ModelBatchResponse{}, fmt.Errorf("%w: %v", ErrSchemaSemanticMismatch, err)
	}
	if err := validateResponseSemantics(req, resp); err != nil {
		return ModelBatchResponse{}, err
	}
	return resp, nil
}

// validateResponseSemantics implements spec §30's semantic rules exactly:
// request_id equality, exact candidate-ID set equality (both directions),
// uniqueness, contributor features existing in the matching request
// candidate's `current`, and status=insufficient_data's zeroed shape.
func validateResponseSemantics(req ModelBatchRequest, resp ModelBatchResponse) error {
	if resp.RequestID != req.RequestID {
		return fmt.Errorf("%w: response request_id %q != request request_id %q", ErrSchemaSemanticMismatch, resp.RequestID, req.RequestID)
	}

	reqByID := make(map[string]ModelCandidateRequest, len(req.Candidates))
	for _, c := range req.Candidates {
		reqByID[c.CandidateID] = c
	}

	seen := map[string]bool{}
	for _, c := range resp.Candidates {
		if seen[c.CandidateID] {
			return fmt.Errorf("%w: duplicate response candidate_id %q", ErrSchemaSemanticMismatch, c.CandidateID)
		}
		seen[c.CandidateID] = true
		if _, ok := reqByID[c.CandidateID]; !ok {
			return fmt.Errorf("%w: response candidate_id %q not in request", ErrSchemaSemanticMismatch, c.CandidateID)
		}
	}
	if len(seen) != len(reqByID) {
		return fmt.Errorf("%w: response candidate-id set does not equal request candidate-id set", ErrSchemaSemanticMismatch)
	}

	for _, c := range resp.Candidates {
		reqCand := reqByID[c.CandidateID]
		for _, contrib := range c.Contributors {
			if _, ok := reqCand.Current[contrib.Feature]; !ok {
				return fmt.Errorf("%w: contributor feature %q not present in candidate %q's current", ErrSchemaSemanticMismatch, contrib.Feature, c.CandidateID)
			}
		}
		if resp.Status == "insufficient_data" {
			if c.Score != 0 || c.Confidence != 0 || len(c.Contributors) != 0 {
				return fmt.Errorf("%w: insufficient_data candidate %q must have score=0, confidence=0, contributors=[]", ErrSchemaSemanticMismatch, c.CandidateID)
			}
		}
	}
	return nil
}
