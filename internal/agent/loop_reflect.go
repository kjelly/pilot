package agent

import (
	"fmt"
	"strings"

	"github.com/anomalyco/pilot/internal/ollama"
)

// reflectOnRejection appends a system reminder to the loop history
// when the user (or an interceptor) rejects a proposal. The reminder
// gives the LLM one concrete nudge — "do not re-submit identical args
// this turn" — and records the rejection reason if available.
//
// Without this, the LLM's most common failure mode is to re-issue
// the exact same tool call (e.g. forgetting become: true twice in a
// row). With it, the next iteration at least sees WHY it was rejected
// and what would change the outcome.
//
// We deliberately keep the message small (one line of context + one
// directive) to avoid polluting the context window with every prior
// mistake. The reflection is also deduplicated by tool+args hash so
// the same mistake isn't reflected twice in a row — otherwise an
// upstream bug could turn one mistake into 50 repeated reflections.
func (l *Loop) reflectOnRejection(p *Proposal, rejectionReason string) {
	if p == nil {
		return
	}
	// Cap the reason to keep the message small.
	reason := strings.TrimSpace(rejectionReason)
	if len(reason) > 240 {
		reason = reason[:240] + "..."
	}
	hash := rejectionHash(p.Tool, string(p.Args))
	if l.recentRejections[hash] >= 2 {
		// Same args rejected twice already; skip further reflection
		// to avoid endless loops.
		return
	}
	if l.recentRejections == nil {
		l.recentRejections = make(map[string]int)
	}
	l.recentRejections[hash]++

	var msg strings.Builder
	fmt.Fprintf(&msg, "Proposal %s (%s) was REJECTED by the user.", p.ID, p.Tool)
	if reason != "" {
		fmt.Fprintf(&msg, " Reason: %q", reason)
	}
	msg.WriteString(" Adjust your approach — do NOT submit the same args again. ")
	msg.WriteString("If you don't know what to change, call ask_user to clarify, or search_docs to look up the correct module/parameter names.")
	l.history = append(l.history, ollama.Message{Role: "system", Content: msg.String()})
	l.persistMessage("system", msg.String(), nil)
}

// reflectOnFailure is the auto-fail path: tool errored (e.g. bleve
// search returned 0 hits, ansible --check failed). Same dedup logic,
// different wording.
func (l *Loop) reflectOnFailure(p *Proposal, errMsg string) {
	if p == nil {
		return
	}
	errMsg = strings.TrimSpace(errMsg)
	if len(errMsg) > 240 {
		errMsg = errMsg[:240] + "..."
	}
	hash := "err:" + rejectionHash(p.Tool, errMsg)
	if l.recentRejections[hash] >= 2 {
		return
	}
	if l.recentRejections == nil {
		l.recentRejections = make(map[string]int)
	}
	l.recentRejections[hash]++

	var msg strings.Builder
	fmt.Fprintf(&msg, "Proposal %s (%s) FAILED to execute.", p.ID, p.Tool)
	if errMsg != "" {
		fmt.Fprintf(&msg, " Error: %q", errMsg)
	}
	msg.WriteString(" Try a different approach — fix the args, use a different module, or call ask_user.")
	l.history = append(l.history, ollama.Message{Role: "system", Content: msg.String()})
	l.persistMessage("system", msg.String(), nil)
}

// rejectionHash produces a short fingerprint of a tool+args pair so
// we can dedupe reflection messages. The args JSON may be long; we
// hash only the first 512 chars to keep this cheap.
func rejectionHash(tool, args string) string {
	const maxLen = 512
	if len(args) > maxLen {
		args = args[:maxLen]
	}
	// FNV-1a-ish; we don't need cryptographic strength here.
	h := uint32(2166136261)
	for _, b := range []byte(tool) {
		h ^= uint32(b)
		h *= 16777619
	}
	for _, b := range []byte(args) {
		h ^= uint32(b)
		h *= 16777619
	}
	return fmt.Sprintf("%08x", h)
}

// clearRecentRejections resets the dedup table. Called at the start of
// each new user turn (RunOnce) so a fresh goal isn't biased by old
// failures.
func (l *Loop) clearRecentRejections() {
	l.recentRejections = make(map[string]int)
}
