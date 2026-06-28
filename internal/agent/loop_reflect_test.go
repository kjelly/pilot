package agent

import (
	"strings"
	"testing"
)

func TestReflectOnRejection_AppendsSystemMessage(t *testing.T) {
	l := &Loop{recentRejections: map[string]int{}}
	l.history = nil
	p := &Proposal{
		ID:    "p-1",
		Tool:  "run_ansible",
		Args:  []byte(`{"playbook":"/tmp/x.yml"}`),
	}
	l.reflectOnRejection(p, "missing become:true")
	if len(l.history) != 1 {
		t.Fatalf("expected 1 message, got %d", len(l.history))
	}
	msg := l.history[0]
	if msg.Role != "system" {
		t.Errorf("role = %q, want system", msg.Role)
	}
	if !strings.Contains(msg.Content, "REJECTED") {
		t.Errorf("content missing REJECTED: %q", msg.Content)
	}
	if !strings.Contains(msg.Content, "missing become:true") {
		t.Errorf("content missing reason: %q", msg.Content)
	}
	if !strings.Contains(msg.Content, "do NOT submit the same args again") {
		t.Errorf("content missing directive: %q", msg.Content)
	}
}

func TestReflectOnRejection_DedupesSameArgs(t *testing.T) {
	l := &Loop{recentRejections: map[string]int{}}
	p := &Proposal{ID: "p", Tool: "run_ansible", Args: []byte(`{"x":1}`)}
	l.reflectOnRejection(p, "bad")
	l.reflectOnRejection(p, "bad again")
	l.reflectOnRejection(p, "still bad") // should be skipped (>2)
	if len(l.history) != 2 {
		t.Errorf("expected 2 reflections (cap=2), got %d", len(l.history))
	}
}

func TestReflectOnFailure_DifferentWording(t *testing.T) {
	l := &Loop{recentRejections: map[string]int{}}
	p := &Proposal{ID: "p", Tool: "search_docs", Args: []byte(`{}`)}
	l.reflectOnFailure(p, "bleve index empty")
	if !strings.Contains(l.history[0].Content, "FAILED") {
		t.Errorf("failure reflection should say FAILED, got: %q", l.history[0].Content)
	}
	if !strings.Contains(l.history[0].Content, "bleve index empty") {
		t.Errorf("failure reflection should include error msg: %q", l.history[0].Content)
	}
}

func TestClearRecentRejections_Resets(t *testing.T) {
	l := &Loop{recentRejections: map[string]int{}}
	p := &Proposal{Tool: "run_ansible", Args: []byte(`{}`)}
	l.reflectOnRejection(p, "x")
	l.reflectOnRejection(p, "x")
	l.clearRecentRejections()
	if len(l.recentRejections) != 0 {
		t.Errorf("clearRecentRejections should empty the map")
	}
	// After clear, another reflection of the same args should fire.
	l.reflectOnRejection(p, "x")
	if len(l.history) != 3 {
		t.Errorf("expected 3 reflections after clear, got %d", len(l.history))
	}
}

func TestRejectionHash_StableForSameInput(t *testing.T) {
	a := rejectionHash("run_ansible", `{"x":1}`)
	b := rejectionHash("run_ansible", `{"x":1}`)
	if a != b {
		t.Errorf("hash not stable: %q vs %q", a, b)
	}
	c := rejectionHash("run_ansible", `{"x":2}`)
	if a == c {
		t.Errorf("different args should produce different hashes")
	}
	d := rejectionHash("search_docs", `{"x":1}`)
	if a == d {
		t.Errorf("different tools should produce different hashes")
	}
}

func TestReflect_TruncatesLongReason(t *testing.T) {
	l := &Loop{recentRejections: map[string]int{}}
	p := &Proposal{Tool: "x", Args: []byte(`{}`)}
	long := strings.Repeat("a", 1000)
	l.reflectOnRejection(p, long)
	// The 240-char cap + "..." should appear
	if !strings.Contains(l.history[0].Content, "...") {
		t.Errorf("long reason should be truncated with ellipsis")
	}
}
