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

func TestNormalizeSubject_PilotHostPrecedence(t *testing.T) {
	sub := normalizeSubject(map[string]string{"pilot_host": "web-1", "site": "hq"})
	want := IncidentSubject{ID: "web-1", Kind: SubjectKindManagedHost, Site: "hq", Managed: true}
	if sub != want {
		t.Fatalf("normalizeSubject(pilot_host) = %+v, want %+v", sub, want)
	}
}

func TestNormalizeSubject_PilotTargetNeverManaged(t *testing.T) {
	sub := normalizeSubject(map[string]string{
		"pilot_target": "core-sw-01", "pilot_subject_kind": "network_device", "site": "hq",
	})
	want := IncidentSubject{ID: "core-sw-01", Kind: "network_device", Site: "hq", Managed: false}
	if sub != want {
		t.Fatalf("normalizeSubject(pilot_target) = %+v, want %+v", sub, want)
	}
}

func TestNormalizeSubject_GenericPilotSubjectTakesPrecedence(t *testing.T) {
	// pilot_subject must win even when pilot_host/pilot_target are ALSO
	// present (spec §10.1's fixed precedence order — rule 1 before 2/3).
	sub := normalizeSubject(map[string]string{
		"pilot_subject": "custom-1", "pilot_subject_kind": "custom_kind", "site": "hq",
		"pilot_host": "web-1", "pilot_target": "core-sw-01",
	})
	want := IncidentSubject{ID: "custom-1", Kind: "custom_kind", Site: "hq", Managed: false}
	if sub != want {
		t.Fatalf("normalizeSubject(pilot_subject) = %+v, want %+v", sub, want)
	}
}

func TestNormalizeSubject_NoSubjectLabelsIsEmpty(t *testing.T) {
	sub := normalizeSubject(map[string]string{"alertname": "Watchdog"})
	if sub != (IncidentSubject{}) {
		t.Fatalf("normalizeSubject(no subject labels) = %+v, want zero value", sub)
	}
}

func TestNormalizeSubject_NeverInventedFromInstanceOrGeneratorURL(t *testing.T) {
	// spec §10.1's explicit prohibition list: instance/reverse-DNS/
	// sysName/generatorURL/annotation prose must never become a subject.
	sub := normalizeSubject(map[string]string{"instance": "10.0.0.1:9100", "job": "node"})
	if sub != (IncidentSubject{}) {
		t.Fatalf("normalizeSubject must not invent a subject from instance/job, got %+v", sub)
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
