package agentcontroller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// AgentDispatcher is the controller's only channel to the external Agent
// Runtime (spec §12). The incident/queue layer never talks to a Runtime
// through anything but this interface — no protocol-specific field ever
// leaks into IncidentEnvelopeV1 or DiagnosisResult.
type AgentDispatcher interface {
	Diagnose(ctx context.Context, in IncidentEnvelopeV1) (DiagnosisResult, error)
}

// FakeDispatcher is a deterministic, in-process AgentDispatcher used by
// unit tests and the disposable-lane actual-run evidence (spec §17) —
// there is no live Agent Runtime wired into Phase 1's own test/evidence
// lanes, only this fake standing in for one.
type FakeDispatcher struct {
	mu sync.Mutex
	// Handler, if set, computes the response for each call. Nil returns
	// a fixed insufficient_evidence result.
	Handler func(IncidentEnvelopeV1) (DiagnosisResult, error)
	calls   []IncidentEnvelopeV1
}

func (f *FakeDispatcher) Diagnose(ctx context.Context, in IncidentEnvelopeV1) (DiagnosisResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, in)
	handler := f.Handler
	f.mu.Unlock()
	if handler != nil {
		return handler(in)
	}
	return DiagnosisResult{
		SchemaVersion: 1,
		Verdict:       VerdictInsufficientEvidence,
		Confidence:    0,
		Summary:       "fake dispatcher: no handler configured",
		Evidence: []DiagnosisEvidence{
			{Tool: "fake_dispatcher", Summary: "deterministic fixed response, no Handler set"},
		},
	}, nil
}

// Calls returns every envelope this fake has been asked to diagnose, in
// order.
func (f *FakeDispatcher) Calls() []IncidentEnvelopeV1 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]IncidentEnvelopeV1, len(f.calls))
	copy(out, f.calls)
	return out
}

// HTTPDispatcher is the generic, vendor-agnostic AgentDispatcher adapter
// (spec §4/§12): POST IncidentEnvelopeV1 as JSON to a fixed, configured
// endpoint and decode a DiagnosisResult JSON response. It never execs a
// process, opens a shell, or reads an environment variable at request
// time, so the "no sh -c", "no string command concatenation", and
// "explicit environment-variable allowlist" adapter requirements are
// satisfied by construction rather than by an explicit allowlist check.
//
// No specific external Agent Runtime product is wired in yet — this is
// intentionally the ONLY adapter Phase 1 ships; a Runtime-specific
// adapter (see internal/agentcontroller/dispatcher.go's AgentDispatcher
// boundary) can be added later without touching IncidentEnvelopeV1 or
// DiagnosisResult.
type HTTPDispatcher struct {
	Endpoint string
	Client   *http.Client
}

// NewHTTPDispatcher builds an HTTPDispatcher with a fixed request
// timeout — the incident can never choose the endpoint or extend the
// timeout.
func NewHTTPDispatcher(endpoint string, timeout time.Duration) *HTTPDispatcher {
	return &HTTPDispatcher{
		Endpoint: endpoint,
		Client:   &http.Client{Timeout: timeout},
	}
}

func (d *HTTPDispatcher) Diagnose(ctx context.Context, in IncidentEnvelopeV1) (DiagnosisResult, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return DiagnosisResult{}, fmt.Errorf("marshal envelope: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.Endpoint, bytes.NewReader(body))
	if err != nil {
		return DiagnosisResult{}, fmt.Errorf("build dispatch request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.Client.Do(req)
	if err != nil {
		return DiagnosisResult{}, fmt.Errorf("dispatch request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return DiagnosisResult{}, fmt.Errorf("read dispatch response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return DiagnosisResult{}, fmt.Errorf("dispatch request: status %d", resp.StatusCode)
	}

	var result DiagnosisResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return DiagnosisResult{}, fmt.Errorf("decode diagnosis result: %w", err)
	}
	return result, nil
}

// Health does a minimal reachability probe against Endpoint, separate
// from a real diagnosis request (spec §12) — it does not itself submit
// an incident.
func (d *HTTPDispatcher) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, d.Endpoint, nil)
	if err != nil {
		return fmt.Errorf("build health request: %w", err)
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return fmt.Errorf("health probe: %w", err)
	}
	resp.Body.Close()
	return nil
}
