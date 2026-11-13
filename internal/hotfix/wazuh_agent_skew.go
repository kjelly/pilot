// Package hotfix holds the deterministic, testable parts of `pilot hotfix`
// subcommands: parsing what a hotfix playbook reports and deciding whether a
// run really did what it was asked to. The cobra wiring and every prompt live
// in cmd/pilot/cmd; nothing here runs a process or asks a question.
//
// The first subcommand is wazuh-agent-skew (spec
// docs/verification/wazuh-fim-agent-skew-hotfix.md): remove Wazuh agents whose
// release is newer than their manager's so `pilot deploy` can reinstall the
// right one. Whether a host is "newer" is decided exactly once, by
// playbooks/apply/files/wazuh-agent-hotfix.py inspect; this package only reads
// that verdict from the playbook's marker lines and never compares versions.
package hotfix

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// WazuhSkewPlaybook is the internal entry playbook `pilot hotfix wazuh-agent-skew`
// runs (AGENTS.md §4.0: no contract, no catalog entry, not in site.yml).
const WazuhSkewPlaybook = "playbooks/apply/wazuh-fim-agent-skew-hotfix.yml"

// ObserveModeVar is the extra var that makes the playbook run only its
// read-only play, which is how the plan is produced before anything is asked.
const ObserveModeVar = "pilot_hotfix_mode=observe"

// Outcome values the playbook reports for a host's removal.
const (
	OutcomeRemoved     = "removed"
	OutcomeWouldRemove = "would-remove"
)

// NoneToken is how the playbook spells "nothing" in a marker line.
const NoneToken = "none"

var (
	ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	// The marker lines are printed by ansible.builtin.debug, so each sits inside a JSON
	// string: the value tokens never contain a quote, and the character class stops at one.
	managerMarker = regexp.MustCompile(`PILOT_HOTFIX_MANAGER host=([^\s"]+) version=([^\s"]+)`)
	stateMarker   = regexp.MustCompile(`PILOT_HOTFIX_STATE host=([^\s"]+) installed=([^\s"]+) skewed=(true|false) registration=([^\s"]+)`)
	resultMarker  = regexp.MustCompile(`PILOT_HOTFIX_RESULT host=([^\s"]+) outcome=([^\s"]+) registration=([^\s"]+)`)
)

// HostState is what the read-only play observed on one agent host.
type HostState struct {
	Host      string
	Installed string // installed wazuh-agent package version; "" when none
	Skewed    bool   // true when the installed release is newer than the manager's
	// Registration is "<id>:<name>" from the host's client.keys, "" when it has none.
	Registration string
}

// Observation is the whole read-only play: the one manager and every host it judged.
type Observation struct {
	ManagerHost    string
	ManagerVersion string
	Hosts          []HostState
}

// Result is what the removal play reported for one host.
type Result struct {
	Host         string
	Outcome      string
	Registration string
}

func clean(s string) string { return ansiEscape.ReplaceAllString(s, "") }

func noneIsEmpty(s string) string {
	if s == NoneToken {
		return ""
	}
	return s
}

// ParseObservation reads the marker lines of a playbook run. It refuses anything
// ambiguous: no manager, two different managers, no hosts, or one host reported
// twice with different answers. A run that judged nobody must not read as "all fine".
func ParseObservation(stdout string) (Observation, error) {
	text := clean(stdout)
	var obs Observation
	for _, m := range managerMarker.FindAllStringSubmatch(text, -1) {
		switch {
		case obs.ManagerHost == "":
			obs.ManagerHost, obs.ManagerVersion = m[1], m[2]
		case obs.ManagerHost != m[1] || obs.ManagerVersion != m[2]:
			return Observation{}, fmt.Errorf("the playbook reported two different managers (%s %s and %s %s)", obs.ManagerHost, obs.ManagerVersion, m[1], m[2])
		}
	}
	if obs.ManagerHost == "" {
		return Observation{}, fmt.Errorf("the playbook did not report the manager version (no PILOT_HOTFIX_MANAGER line)")
	}
	seen := map[string]HostState{}
	for _, m := range stateMarker.FindAllStringSubmatch(text, -1) {
		state := HostState{Host: m[1], Installed: noneIsEmpty(m[2]), Skewed: m[3] == "true", Registration: noneIsEmpty(m[4])}
		if prev, dup := seen[state.Host]; dup {
			if prev != state {
				return Observation{}, fmt.Errorf("host %s was reported twice with different states", state.Host)
			}
			continue
		}
		seen[state.Host] = state
		obs.Hosts = append(obs.Hosts, state)
	}
	if len(obs.Hosts) == 0 {
		return Observation{}, fmt.Errorf("the playbook judged no agent host (no PILOT_HOTFIX_STATE line); check --limit and the wazuh-fim group")
	}
	for _, h := range obs.Hosts {
		if h.Skewed && h.Installed == "" {
			return Observation{}, fmt.Errorf("host %s is reported newer than the manager but with no installed agent", h.Host)
		}
	}
	return obs, nil
}

// Skewed returns the hosts judged newer than the manager, sorted by name.
func (o Observation) Skewed() []HostState {
	var out []HostState
	for _, h := range o.Hosts {
		if h.Skewed {
			out = append(out, h)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// SkewedHosts returns just the names of Skewed.
func (o Observation) SkewedHosts() []string {
	var names []string
	for _, h := range o.Skewed() {
		names = append(names, h.Host)
	}
	return names
}

// RenderPlan prints the host table of the plan the operator is asked to confirm.
func (o Observation) RenderPlan(w io.Writer) {
	fmt.Fprintf(w, "manager %s 的 Wazuh 版本：%s\n\n", o.ManagerHost, o.ManagerVersion)
	hosts := append([]HostState(nil), o.Hosts...)
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Host < hosts[j].Host })
	width := len("主機")
	for _, h := range hosts {
		if len(h.Host) > width {
			width = len(h.Host)
		}
	}
	fmt.Fprintf(w, "%-*s  %-14s  %s\n", width, "主機", "agent 版本", "動作")
	for _, h := range hosts {
		version := h.Installed
		action := "不動（版本相容）"
		switch {
		case h.Skewed:
			action = "移除 agent 並在 manager 取消登記"
			if h.Registration == "" {
				action = "移除 agent（沒有 enrollment，manager 不需動）"
			}
		case h.Installed == "":
			version = "（未安裝）"
			action = "不動"
		}
		fmt.Fprintf(w, "%-*s  %-14s  %s\n", width, h.Host, version, action)
	}
}

// refusalMarker finds the typed refusal files/wazuh-agent-hotfix.py prints as JSON. Inside a failed
// task's result it sits in an escaped JSON string, so the quotes around it are backslash-escaped.
var refusalMarker = regexp.MustCompile(`\\"error\\": \\"((?:[^"\\]|\\.)*?)\\", \\"error_kind\\": \\"(?:refused|native)\\"`)

// Refusals returns the typed reasons the helper refused with, in order and without repeats, so a
// failed run can say why: ansible's own failure line only says "non-zero return code".
func Refusals(output string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range refusalMarker.FindAllStringSubmatch(clean(output), -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// ParseResults reads the per-host removal outcomes of the apply run.
func ParseResults(stdout string) []Result {
	var out []Result
	seen := map[string]bool{}
	for _, m := range resultMarker.FindAllStringSubmatch(clean(stdout), -1) {
		if seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		out = append(out, Result{Host: m[1], Outcome: m[2], Registration: noneIsEmpty(m[3])})
	}
	return out
}

// Summary is what an apply run really did, built only from the markers the run printed.
type Summary struct {
	Removed       []string // hosts that reported outcome=removed
	Compatible    []string // hosts the run judged not newer than the manager (left untouched)
	Incomplete    []string // judged newer, but the run never reported them removed
	UnexpectedNew []string // removed although the plan did not list them (state changed in between)
}

// Summarize judges an apply run against the plan that was confirmed. A host the
// confirmed plan listed and the run did not report removed is Incomplete, which the
// caller turns into a failure: success is only ever derived from what was reported.
func Summarize(plan Observation, apply Observation, results []Result) Summary {
	removed := map[string]bool{}
	for _, r := range results {
		if r.Outcome == OutcomeRemoved {
			removed[r.Host] = true
		}
	}
	planned := map[string]bool{}
	for _, h := range plan.SkewedHosts() {
		planned[h] = true
	}
	var s Summary
	for _, h := range apply.Hosts {
		switch {
		case h.Skewed && removed[h.Host]:
			s.Removed = append(s.Removed, h.Host)
			if !planned[h.Host] {
				s.UnexpectedNew = append(s.UnexpectedNew, h.Host)
			}
		case h.Skewed:
			s.Incomplete = append(s.Incomplete, h.Host)
		default:
			s.Compatible = append(s.Compatible, h.Host)
		}
	}
	for h := range planned {
		if !removed[h] && !contains(s.Incomplete, h) && !contains(s.Compatible, h) {
			s.Incomplete = append(s.Incomplete, h)
		}
	}
	sort.Strings(s.Removed)
	sort.Strings(s.Compatible)
	sort.Strings(s.Incomplete)
	sort.Strings(s.UnexpectedNew)
	return s
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// Render prints the final per-host outcome.
func (s Summary) Render(w io.Writer) {
	if len(s.Removed) > 0 {
		fmt.Fprintf(w, "✅ 已移除 agent：%s\n", strings.Join(s.Removed, ", "))
	}
	if len(s.Compatible) > 0 {
		fmt.Fprintf(w, "↪ 版本相容或未安裝，沒有動：%s\n", strings.Join(s.Compatible, ", "))
	}
	if len(s.UnexpectedNew) > 0 {
		fmt.Fprintf(w, "ℹ️  下列主機在確認計畫之後才變成「比 manager 新」，套用時重新偵測並一併移除：%s\n", strings.Join(s.UnexpectedNew, ", "))
	}
	if len(s.Incomplete) > 0 {
		fmt.Fprintf(w, "❌ 計畫要移除、但這次沒有回報完成：%s\n", strings.Join(s.Incomplete, ", "))
	}
}
