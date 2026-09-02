package agentcontroller

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// alertmanagerWebhook is Alertmanager's standard webhook receiver payload
// shape (send_resolved: true). This is the wire format Alertmanager
// itself defines, not a Pilot invention.
type alertmanagerWebhook struct {
	Version           string              `json:"version"`
	GroupKey          string              `json:"groupKey"`
	Status            string              `json:"status"`
	Receiver          string              `json:"receiver"`
	GroupLabels       map[string]string   `json:"groupLabels"`
	CommonLabels      map[string]string   `json:"commonLabels"`
	CommonAnnotations map[string]string   `json:"commonAnnotations"`
	ExternalURL       string              `json:"externalURL"`
	Alerts            []alertmanagerAlert `json:"alerts"`
}

type alertmanagerAlert struct {
	Status       string            `json:"status"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     string            `json:"startsAt"`
	EndsAt       string            `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint"`
}

// sourceDetectionEngine/sourcePrometheusRule are the only two
// IncidentEvent.Source values (spec §2/§6) — the controller consumes
// exactly these two upstreams, never a third source of its own.
const (
	sourceDetectionEngine = "detection-engine"
	sourcePrometheusRule  = "prometheus-rule"
)

// ParseAlertmanagerWebhook decodes body and normalizes every alert inside
// it into an IncidentEvent (spec §6). Malformed JSON is a hard error —
// the ingress layer (http.go) is the fail-closed boundary, not this
// function.
func ParseAlertmanagerWebhook(body []byte, receivedAt time.Time) ([]IncidentEvent, error) {
	var payload alertmanagerWebhook
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode alertmanager webhook: %w", err)
	}
	if len(payload.Alerts) == 0 {
		return nil, fmt.Errorf("alertmanager webhook has no alerts")
	}

	events := make([]IncidentEvent, 0, len(payload.Alerts))
	for _, a := range payload.Alerts {
		ev, err := normalizeAlert(payload.GroupKey, a, receivedAt)
		if err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	return events, nil
}

func normalizeAlert(groupKey string, a alertmanagerAlert, receivedAt time.Time) (IncidentEvent, error) {
	if a.Fingerprint == "" {
		return IncidentEvent{}, fmt.Errorf("alert missing fingerprint")
	}
	if a.Status != "firing" && a.Status != "resolved" {
		return IncidentEvent{}, fmt.Errorf("alert %s: invalid status %q", a.Fingerprint, a.Status)
	}

	source := sourcePrometheusRule
	if a.Labels["source"] == sourceDetectionEngine {
		source = sourceDetectionEngine
	}

	// Identity rule (spec §6): Detection Engine's own Alertmanager
	// payload (internal/detection/engine.go's buildAlertPayload) carries
	// NO stable Alertmanager-level fingerprint of its own — its label
	// set includes `severity`, so a warning->critical transition on the
	// SAME anomaly changes Alertmanager's computed fingerprint even
	// though it is logically the same episode. annotations["signal_id"]
	// is the one field that stays constant across that transition, so it
	// — not a.Fingerprint — is this event's Episode/identity for
	// Detection Engine alerts. Deterministic Prometheus-rule alerts have
	// no such concept; a.Fingerprint IS their identity.
	//
	// NOTE (baseline adaptation, AGENTS.md's "adapt to current source"):
	// the phase-1 design doc also asks to "preserve the source revision"
	// for Detection Engine alerts, but the current wire payload carries
	// no revision number at all (only labels+annotations+startsAt/
	// endsAt) — there is nothing upstream to preserve yet. The
	// controller's own current_revision (store.go) is therefore a
	// LOCALLY computed monotonic counter, bumped whenever a new,
	// non-replay body is observed for the same identity — not a
	// pass-through of an upstream field.
	episode := a.Fingerprint
	if source == sourceDetectionEngine {
		if sig := a.Annotations["signal_id"]; sig != "" {
			episode = sig
		}
	}

	startsAt, err := time.Parse(time.RFC3339, a.StartsAt)
	if err != nil {
		return IncidentEvent{}, fmt.Errorf("alert %s: parse startsAt %q: %w", a.Fingerprint, a.StartsAt, err)
	}
	var endsAt *time.Time
	if a.EndsAt != "" {
		if t, err := time.Parse(time.RFC3339, a.EndsAt); err == nil && !t.IsZero() {
			endsAt = &t
		}
	}

	ev := IncidentEvent{
		Source:      source,
		GroupKey:    groupKey,
		Fingerprint: a.Fingerprint,
		Episode:     episode,
		Status:      a.Status,
		AlertName:   a.Labels["alertname"],
		Severity:    a.Labels["severity"],
		// Host: canonical pilot_host label only (spec §6) — never
		// invented from `instance`/reverse-DNS. A missing host is valid
		// for a global/service-scoped incident.
		Host:        a.Labels["pilot_host"],
		Site:        a.Labels["site"],
		Component:   a.Labels["component"],
		Category:    a.Annotations["category_hint"],
		Subject:     normalizeSubject(a.Labels),
		StartsAt:    startsAt,
		EndsAt:      endsAt,
		Labels:      a.Labels,
		Annotations: a.Annotations,
		ReceivedAt:  receivedAt,
	}
	ev.AlertBodySHA256 = identityHash(ev)
	return ev, nil
}

// normalizeSubject applies the SNMP monitoring integration spec §10.1
// fixed label precedence — in this exact order, first match wins.
// Deliberately never falls back to `instance`, reverse DNS, `sysName`,
// generatorURL, or annotation prose (spec §10.1's explicit prohibition
// list): a subject this function cannot name from labels alone is a
// global/service-scoped incident with no subject, not a guessed one.
func normalizeSubject(labels map[string]string) IncidentSubject {
	switch {
	case labels["pilot_subject"] != "":
		return IncidentSubject{
			ID:      labels["pilot_subject"],
			Kind:    labels["pilot_subject_kind"],
			Site:    labels["site"],
			Managed: labels["pilot_subject_kind"] == SubjectKindManagedHost,
		}
	case labels["pilot_host"] != "":
		return IncidentSubject{
			ID:      labels["pilot_host"],
			Kind:    SubjectKindManagedHost,
			Site:    labels["site"],
			Managed: true,
		}
	case labels["pilot_target"] != "":
		return IncidentSubject{
			ID:      labels["pilot_target"],
			Kind:    labels["pilot_subject_kind"],
			Site:    labels["site"],
			Managed: false,
		}
	default:
		return IncidentSubject{}
	}
}

// identityHash hashes exactly the fields that define "this is the same
// observation as last time" (spec §7/C5's replay dedup key) — NOT the
// full struct, so fields like ReceivedAt never defeat dedup.
func identityHash(ev IncidentEvent) string {
	canonical := struct {
		Source   string
		Episode  string
		Status   string
		Severity string
		StartsAt string
	}{
		Source:   ev.Source,
		Episode:  ev.Episode,
		Status:   ev.Status,
		Severity: ev.Severity,
		StartsAt: ev.StartsAt.UTC().Format(time.RFC3339),
	}
	b, _ := json.Marshal(canonical)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
