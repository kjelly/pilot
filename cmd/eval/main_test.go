package main

import "testing"

func TestSummarizeDistinguishesIncompleteAndFailure(t *testing.T) {
	status, score := summarize([]gate{{Status: "pass"}, {Status: "not_run"}})
	if status != "incomplete" || score != 50 {
		t.Fatalf("status=%s score=%d", status, score)
	}
	status, _ = summarize([]gate{{Status: "pass"}, {Status: "fail"}, {Status: "not_run"}})
	if status != "fail" {
		t.Fatalf("status=%s", status)
	}
}
