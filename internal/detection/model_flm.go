package detection

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// FLMTimeout is the default request timeout for the flm protocol. Unlike
// OpenAI/Ollama (one candidate per HTTP call), FLMProvider.Score handles
// up to ModelBatchSize candidates as SEQUENTIAL single-candidate calls
// within one Score() invocation (spec1.md has no multi-candidate batch
// contract), so the budget must cover the whole sequence, not just one
// call — empirically a single candidate took 9-14s against a real
// FastFlowLM/NPU backend, so 4 sequential calls plus one retry each needs
// real headroom.
const FLMTimeout = 90 * time.Second

// flmMaxResponseBytes is spec1.md §32's raw-response size cap — anything
// larger is invalid without even attempting to parse it.
const flmMaxResponseBytes = 4096

var flmCategoryPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Score/confidence mappings from spec1.md's coarse enums onto the
// existing continuous fusion math (spec §19's
// effective_model_score = score * confidence, +0.05 category-escalation
// margin). spec1.md deliberately avoids asking the model for a float
// (§7.3: "禁止要求模型輸出 0.873492"), so Pilot code owns this mapping,
// not the model.
var flmSeverityScore = map[string]float64{
	"INFO":     0.30,
	"WARNING":  0.50,
	"HIGH":     0.75,
	"CRITICAL": 0.95,
}

var flmConfidenceScore = map[string]float64{
	"LOW":    0.40,
	"MEDIUM": 0.70,
	"HIGH":   0.95,
}

var flmVerdicts = map[string]bool{"ANOMALY": true, "BENIGN": true, "UNCERTAIN": true}
var flmSeverities = map[string]bool{"INFO": true, "WARNING": true, "HIGH": true, "CRITICAL": true}
var flmConfidences = map[string]bool{"LOW": true, "MEDIUM": true, "HIGH": true}

// flmVerdict is one candidate's parsed-and-validated Stage 1 result
// (spec1.md §21).
type flmVerdict struct {
	Verdict    string
	Severity   string
	Category   string
	Confidence string
}

// FLMProvider implements ModelProvider for a FastFlowLM-class backend
// (spec1.md): a compact pipe-delimited VERDICT|SEVERITY|CATEGORY|CONFIDENCE
// text contract instead of JSON, because the backend provides no
// grammar-constrained/structured-output guarantee — confirmed empirically
// against a real Lemonade Server flm:npu backend, whose underlying engine
// silently ignores a `format` JSON Schema hint entirely. It speaks the
// same Ollama-compatible POST <base_url>/api/chat wire shape as
// OllamaProvider, minus the `format` field, one candidate per HTTP call
// (spec1.md's Stage 1 contract has no multi-candidate batch shape).
type FLMProvider struct {
	BaseURL    string
	Model      string
	APIKey     string // empty = no Authorization header (auth=none)
	HTTPClient *http.Client
}

func (p *FLMProvider) client() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return http.DefaultClient
}

type flmChatRequest struct {
	Model    string              `json:"model"`
	Messages []ollamaChatMessage `json:"messages"`
	Stream   bool                `json:"stream"`
	Options  ollamaChatOptions   `json:"options"`
}

type flmChatResponse struct {
	Message *ollamaChatMessage `json:"message"`
	Error   string             `json:"error"`
}

// Score calls the backend once per candidate and assembles the results
// into the existing ModelBatchResponse envelope, so the rest of the
// engine (batching/fusion/circuit-breaker) is unaware of the difference:
// every requested candidate_id still gets a response (spec §29/§30's
// exact-set-equality holds). A candidate whose response never parses
// after the corrective retry (spec1.md §33) degrades to an
// UNCERTAIN-equivalent zero score rather than failing the whole batch —
// other candidates' real results are not wasted by one bad reply. Only a
// transport-level failure, or EVERY candidate failing to parse, fails the
// whole Score() call (so the circuit breaker can still see a persistently
// broken backend).
func (p *FLMProvider) Score(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error) {
	resp := ModelBatchResponse{
		SchemaVersion: 1,
		RequestID:     req.RequestID,
		Status:        "ok",
		Candidates:    make([]ModelCandidateResponse, 0, len(req.Candidates)),
	}

	parsedCount := 0
	var lastErr error
	for _, c := range req.Candidates {
		v, err := p.scoreOneCandidate(ctx, c)
		if err != nil {
			lastErr = err
			// Degrade this one candidate to UNCERTAIN-equivalent (score=0,
			// confidence=0) rather than failing the whole batch.
			resp.Candidates = append(resp.Candidates, ModelCandidateResponse{
				CandidateID:  c.CandidateID,
				Score:        0,
				Confidence:   0,
				CategoryHint: "",
				Contributors: []ModelContributor{},
			})
			continue
		}
		parsedCount++
		score, confidence := flmEffectiveScore(v)
		category := v.Category
		if v.Verdict != "ANOMALY" {
			// BENIGN/UNCERTAIN never escalate (spec §19: model can only
			// escalate, never suppress) — zero them out identically to
			// how a genuine insufficient_data candidate would fuse.
			score, confidence, category = 0, 0, ""
		}
		resp.Candidates = append(resp.Candidates, ModelCandidateResponse{
			CandidateID:  c.CandidateID,
			Score:        score,
			Confidence:   confidence,
			CategoryHint: category,
			Contributors: []ModelContributor{},
		})
	}

	if parsedCount == 0 && len(req.Candidates) > 0 {
		if lastErr != nil {
			return ModelBatchResponse{}, lastErr
		}
		return ModelBatchResponse{}, newProviderError(KindInvalidStructured, "flm: no candidate in the batch produced a parseable response")
	}
	return resp, nil
}

// flmEffectiveScore maps an ANOMALY verdict's SEVERITY/CONFIDENCE onto the
// existing 0-1 float fusion math.
func flmEffectiveScore(v flmVerdict) (score, confidence float64) {
	return flmSeverityScore[v.Severity], flmConfidenceScore[v.Confidence]
}

// scoreOneCandidate sends one candidate's evidence, with spec1.md §33's
// "1 initial + 1 corrective retry" handled entirely within this call
// (never touching ManagedProvider's own transport-level retry loop, which
// stays reserved for network/timeout/429/5xx).
func (p *FLMProvider) scoreOneCandidate(ctx context.Context, c ModelCandidateRequest) (flmVerdict, error) {
	evidence := formatFLMEvidence(c)
	messages := []ollamaChatMessage{
		{Role: "system", Content: HostAnomalyFLMPrompt()},
		{Role: "user", Content: "<BEGIN_EVIDENCE>\n" + evidence + "\n<END_EVIDENCE>"},
	}

	raw, err := p.chat(ctx, messages)
	if err != nil {
		return flmVerdict{}, err
	}
	v, parseErr := parseAndValidateFLM(raw)
	if parseErr == nil {
		return v, nil
	}

	// spec1.md §33: one corrective retry, prompt now includes the
	// malformed output and an explicit re-ask.
	messages = append(messages,
		ollamaChatMessage{Role: "assistant", Content: raw},
		ollamaChatMessage{Role: "user", Content: fmt.Sprintf(
			"Your previous response was invalid: %s\n\nReturn exactly one line, no other text:\n\nVERDICT|SEVERITY|CATEGORY|CONFIDENCE", parseErr)},
	)
	raw2, err := p.chat(ctx, messages)
	if err != nil {
		return flmVerdict{}, err
	}
	v, parseErr = parseAndValidateFLM(raw2)
	if parseErr != nil {
		return flmVerdict{}, newProviderError(KindInvalidStructured, "flm: invalid response after retry: %w", parseErr)
	}
	return v, nil
}

func (p *FLMProvider) chat(ctx context.Context, messages []ollamaChatMessage) (string, error) {
	payload := flmChatRequest{
		Model:    p.Model,
		Messages: messages,
		Stream:   false,
		Options:  ollamaChatOptions{Temperature: 0},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", newProviderError(KindClientError, "marshal payload: %v", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.BaseURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return "", newProviderError(KindClientError, "build request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if p.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.APIKey)
	}

	resp, err := p.client().Do(httpReq)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", newProviderError(KindTimeout, "flm request timed out: %v", err)
		}
		return "", newProviderError(KindNetwork, "flm request failed: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", newProviderError(classifyHTTPStatus(resp.StatusCode), "flm http %d: %s", resp.StatusCode, truncateForError(respBody))
	}

	var env flmChatResponse
	if err := json.Unmarshal(respBody, &env); err != nil {
		return "", newProviderError(KindInvalidStructured, "flm response envelope: %v", err)
	}
	if env.Error != "" {
		return "", newProviderError(KindProviderRejected, "flm error: %s", env.Error)
	}
	if env.Message == nil {
		return "", newProviderError(KindInvalidStructured, "flm response has no message")
	}
	return env.Message.Content, nil
}

// formatFLMEvidence renders a candidate's already-computed telemetry as
// plain text lines (spec1.md §9: feed the model precomputed values, never
// raw series, and never require it to round-trip JSON). subject_id/
// subject_kind replace the historical pilot_host-only identity (spec
// §9.11's FLM evidence example) — this is exactly the generic aggregate
// evidence the model is allowed to see: no raw SNMP OID, no credential,
// no community string, no full snmpwalk, ever.
func formatFLMEvidence(c ModelCandidateRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "candidate_id=%s\n", c.CandidateID)
	fmt.Fprintf(&b, "subject_id=%s\n", c.SubjectID)
	fmt.Fprintf(&b, "subject_kind=%s\n", c.SubjectKind)
	fmt.Fprintf(&b, "site=%s\n", c.Site)
	names := make([]string, 0, len(c.Current))
	for name := range c.Current {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&b, "%s=%s\n", name, strconv.FormatFloat(c.Current[name], 'g', -1, 64))
	}
	return b.String()
}

// parseAndValidateFLM implements spec1.md §30-§32: a tolerant parser (code
// fences, a "Result:" prefix, or the VERDICT:/SEVERITY:/... compatibility
// form all accepted) followed by a strict allowlist+regex+size validator.
func parseAndValidateFLM(raw string) (flmVerdict, error) {
	if len(raw) > flmMaxResponseBytes {
		return flmVerdict{}, fmt.Errorf("response is %d bytes, exceeds the %d byte limit", len(raw), flmMaxResponseBytes)
	}

	fields, err := parseFLMFields(raw)
	if err != nil {
		return flmVerdict{}, err
	}
	if len(fields) != 4 {
		return flmVerdict{}, fmt.Errorf("expected 4 fields (VERDICT|SEVERITY|CATEGORY|CONFIDENCE), got %d", len(fields))
	}

	v := flmVerdict{
		// VERDICT/SEVERITY/CONFIDENCE are normalized before the allowlist
		// check — the "shape" of these three is the parser's job, only
		// their membership in the enum is what validation checks.
		// CATEGORY is validated exactly as received: spec1.md §32's regex
		// is lowercase-only by design, and silently lowercasing it first
		// would make the validator a no-op on case, contradicting "the
		// Validator MUST strict" (§30) — a model that doesn't follow the
		// documented lowercase-category instruction should fail closed.
		Verdict:    strings.ToUpper(strings.TrimSpace(fields[0])),
		Severity:   strings.ToUpper(strings.TrimSpace(fields[1])),
		Category:   strings.TrimSpace(fields[2]),
		Confidence: strings.ToUpper(strings.TrimSpace(fields[3])),
	}
	if !flmVerdicts[v.Verdict] {
		return flmVerdict{}, fmt.Errorf("invalid VERDICT %q", v.Verdict)
	}
	if !flmSeverities[v.Severity] {
		return flmVerdict{}, fmt.Errorf("invalid SEVERITY %q", v.Severity)
	}
	if !flmConfidences[v.Confidence] {
		return flmVerdict{}, fmt.Errorf("invalid CONFIDENCE %q", v.Confidence)
	}
	if !flmCategoryPattern.MatchString(v.Category) {
		return flmVerdict{}, fmt.Errorf("invalid CATEGORY %q", v.Category)
	}
	return v, nil
}

// parseFLMFields extracts the 4 pipe-delimited fields from a raw response,
// tolerating code fences and a "Result:"-style prefix (spec1.md §30/§31),
// and the "VERDICT: X" / "SEVERITY: Y" / ... compatibility form.
func parseFLMFields(raw string) ([]string, error) {
	line := strings.TrimSpace(raw)
	line = strings.Trim(line, "`")
	line = strings.TrimSpace(line)
	if strings.Contains(line, "|") {
		// Canonical form, optionally prefixed ("Result: A|B|C|D") and/or
		// carrying a trailing line of explanation the model wasn't
		// supposed to add — only the first line with a pipe is used.
		for _, candidate := range strings.Split(line, "\n") {
			if !strings.Contains(candidate, "|") {
				continue
			}
			if i := strings.LastIndex(candidate, ":"); i >= 0 && i < strings.IndexByte(candidate, '|') {
				candidate = candidate[i+1:]
			}
			return strings.Split(strings.TrimSpace(candidate), "|"), nil
		}
	}

	// VERDICT: X / SEVERITY: Y / CATEGORY: Z / CONFIDENCE: W compatibility form.
	fieldOrder := []string{"VERDICT", "SEVERITY", "CATEGORY", "CONFIDENCE"}
	found := map[string]string{}
	for _, l := range strings.Split(raw, "\n") {
		l = strings.TrimSpace(l)
		for _, key := range fieldOrder {
			if strings.HasPrefix(strings.ToUpper(l), key+":") {
				found[key] = strings.TrimSpace(l[len(key)+1:])
			}
		}
	}
	if len(found) == 4 {
		out := make([]string, 4)
		for i, key := range fieldOrder {
			out[i] = found[key]
		}
		return out, nil
	}
	return nil, fmt.Errorf("no recognizable VERDICT|SEVERITY|CATEGORY|CONFIDENCE line")
}
