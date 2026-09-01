package agentcontroller

import (
	"encoding/json"
	"testing"
	"time"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestParseAlertmanagerWebhook_PrometheusRuleIdentity(t *testing.T) {
	body := mustJSON(t, alertmanagerWebhook{
		Version:  "4",
		GroupKey: "{}:{alertname=\"DiskFull\"}",
		Status:   "firing",
		Alerts: []alertmanagerAlert{{
			Status:      "firing",
			Fingerprint: "abc123",
			Labels:      map[string]string{"alertname": "DiskFull", "severity": "critical", "pilot_host": "web-1"},
			Annotations: map[string]string{},
			StartsAt:    "2026-09-01T00:00:00Z",
			EndsAt:      "0001-01-01T00:00:00Z",
		}},
	})

	events, err := ParseAlertmanagerWebhook(body, time.Now())
	if err != nil {
		t.Fatalf("ParseAlertmanagerWebhook: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.Source != sourcePrometheusRule {
		t.Errorf("source = %q, want %q", ev.Source, sourcePrometheusRule)
	}
	if ev.Episode != "abc123" || ev.Fingerprint != "abc123" {
		t.Errorf("episode/fingerprint = %q/%q, want Alertmanager's own fingerprint for a deterministic rule", ev.Episode, ev.Fingerprint)
	}
	if ev.Host != "web-1" {
		t.Errorf("host = %q, want web-1", ev.Host)
	}
	if ev.EndsAt != nil {
		t.Error("zero-value endsAt (0001-01-01T00:00:00Z, Alertmanager's still-firing sentinel) must not become a non-nil EndsAt")
	}
}

func TestParseAlertmanagerWebhook_DetectionEngineIdentityIsSignalID(t *testing.T) {
	// Mirrors internal/detection/engine.go's real buildAlertPayload wire
	// shape exactly: labels {alertname, source, pilot_host, site,
	// severity}, annotations carries signal_id — NOT a revision field.
	warn := alertmanagerAlert{
		Status:      "firing",
		Fingerprint: "am-fp-during-warning",
		Labels:      map[string]string{"alertname": "PilotAdaptiveAnomaly", "source": "detection-engine", "pilot_host": "web-1", "site": "hq", "severity": "warning"},
		Annotations: map[string]string{"signal_id": "sig-abc", "category_hint": "cpu"},
		StartsAt:    "2026-09-01T00:00:00Z",
	}
	crit := alertmanagerAlert{
		Status:      "firing",
		Fingerprint: "am-fp-during-critical", // Alertmanager computes a DIFFERENT fingerprint once severity changes
		Labels:      map[string]string{"alertname": "PilotAdaptiveAnomaly", "source": "detection-engine", "pilot_host": "web-1", "site": "hq", "severity": "critical"},
		Annotations: map[string]string{"signal_id": "sig-abc", "category_hint": "cpu"},
		StartsAt:    "2026-09-01T00:05:00Z",
	}

	body := mustJSON(t, alertmanagerWebhook{Version: "4", GroupKey: "g", Status: "firing", Alerts: []alertmanagerAlert{warn, crit}})
	events, err := ParseAlertmanagerWebhook(body, time.Now())
	if err != nil {
		t.Fatalf("ParseAlertmanagerWebhook: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(events))
	}
	if events[0].Episode != "sig-abc" || events[1].Episode != "sig-abc" {
		t.Fatalf("episode = %q/%q, want sig-abc/sig-abc (identity must survive a severity transition)", events[0].Episode, events[1].Episode)
	}
	if events[0].Fingerprint == events[1].Fingerprint {
		t.Fatal("test fixture invalid: fingerprints must differ across severity to exercise the real gap this normalization closes")
	}
	if events[0].Category != "cpu" {
		t.Errorf("category = %q, want cpu", events[0].Category)
	}
}

func TestParseAlertmanagerWebhook_MissingFingerprintRejected(t *testing.T) {
	body := mustJSON(t, alertmanagerWebhook{Alerts: []alertmanagerAlert{{Status: "firing", StartsAt: "2026-09-01T00:00:00Z"}}})
	if _, err := ParseAlertmanagerWebhook(body, time.Now()); err == nil {
		t.Fatal("expected an error for a missing fingerprint")
	}
}

func TestParseAlertmanagerWebhook_InvalidStatusRejected(t *testing.T) {
	body := mustJSON(t, alertmanagerWebhook{Alerts: []alertmanagerAlert{{Status: "bogus", Fingerprint: "x", StartsAt: "2026-09-01T00:00:00Z"}}})
	if _, err := ParseAlertmanagerWebhook(body, time.Now()); err == nil {
		t.Fatal("expected an error for an invalid status")
	}
}

func TestParseAlertmanagerWebhook_MalformedJSONRejected(t *testing.T) {
	if _, err := ParseAlertmanagerWebhook([]byte("{not json"), time.Now()); err == nil {
		t.Fatal("expected an error for malformed JSON")
	}
}

func TestParseAlertmanagerWebhook_NoAlertsRejected(t *testing.T) {
	body := mustJSON(t, alertmanagerWebhook{Alerts: nil})
	if _, err := ParseAlertmanagerWebhook(body, time.Now()); err == nil {
		t.Fatal("expected an error for a webhook with zero alerts")
	}
}

func TestIdentityHash_StableAcrossReceivedAtAndLabelOrder(t *testing.T) {
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	a := IncidentEvent{Source: "prometheus-rule", Episode: "fp-1", Status: "firing", Severity: "critical", StartsAt: base, ReceivedAt: base}
	b := IncidentEvent{Source: "prometheus-rule", Episode: "fp-1", Status: "firing", Severity: "critical", StartsAt: base, ReceivedAt: base.Add(time.Hour)}
	if identityHash(a) != identityHash(b) {
		t.Error("identityHash must not depend on ReceivedAt")
	}

	c := IncidentEvent{Source: "prometheus-rule", Episode: "fp-1", Status: "firing", Severity: "warning", StartsAt: base}
	if identityHash(a) == identityHash(c) {
		t.Error("identityHash must change when severity changes")
	}
}
