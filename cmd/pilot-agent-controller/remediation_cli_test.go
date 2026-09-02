package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/agentcontroller"
)

// TestRequireManagedIncidentSubject locks the SNMP monitoring
// integration spec §10.6 fail-closed guard: `remediation propose`/
// `reapply-propose` must refuse an incident whose subject is not a
// managed host, before any repair/reapply plan is ever created.
func TestRequireManagedIncidentSubject(t *testing.T) {
	store, err := agentcontroller.OpenStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()

	now := time.Now()

	managedEvent := agentcontroller.IncidentEvent{
		Source: "prometheus-rule", GroupKey: "g", Fingerprint: "fp-managed", Episode: "fp-managed",
		Status: "firing", AlertName: "HostDown", Severity: "critical", Host: "web-1",
		Subject:    agentcontroller.IncidentSubject{ID: "web-1", Kind: agentcontroller.SubjectKindManagedHost, Managed: true},
		StartsAt:   now,
		ReceivedAt: now,
	}
	managedOut, err := store.IngestEvent(managedEvent, now)
	if err != nil {
		t.Fatalf("ingest managed event: %v", err)
	}
	if err := requireManagedIncidentSubject(store, managedOut.IncidentID); err != nil {
		t.Errorf("managed-host incident must be allowed, got error: %v", err)
	}

	externalEvent := agentcontroller.IncidentEvent{
		Source: "prometheus-rule", GroupKey: "g", Fingerprint: "fp-external", Episode: "fp-external",
		Status: "firing", AlertName: "SNMPTargetDown", Severity: "critical",
		Subject:    agentcontroller.IncidentSubject{ID: "core-sw-01", Kind: "network_device", Site: "hq", Managed: false},
		StartsAt:   now,
		ReceivedAt: now,
	}
	externalOut, err := store.IngestEvent(externalEvent, now)
	if err != nil {
		t.Fatalf("ingest external event: %v", err)
	}
	if err := requireManagedIncidentSubject(store, externalOut.IncidentID); err == nil {
		t.Error("external subject incident must be refused, got nil error")
	}

	if err := requireManagedIncidentSubject(store, "does-not-exist"); err == nil {
		t.Error("unknown incident id must be refused, got nil error")
	}
}
