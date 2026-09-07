package diagnosesession

import (
	"strings"
	"testing"
)

func TestSessionAppendAndGetIsBoundedAndReplayable(t *testing.T) {
	root := t.TempDir()
	rec, err := Start(root, "incident-1", "snmp/hq_forti_firewall")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Append(root, rec.ID, "pilot_workspace_integrity", strings.Repeat("x", 5000)); err != nil {
		t.Fatal(err)
	}
	got, err := Get(root, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Events) != 1 || got.Events[0].Seq != 1 {
		t.Fatalf("events = %+v", got.Events)
	}
	if len(got.Events[0].Summary) > maxSummaryBytes+len("…") {
		t.Fatalf("summary was not bounded: %d", len(got.Events[0].Summary))
	}
}

func TestSessionRejectsPathTraversal(t *testing.T) {
	if _, err := Start(t.TempDir(), "../escape", ""); err == nil {
		t.Fatal("path traversal id unexpectedly accepted")
	}
}
