package hotfix

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"
)

// ansible-debug-markers.txt is a real ansible-playbook capture (ansible-core, ANSIBLE_NOCOLOR=1) of
// the same ansible.builtin.debug expressions the hotfix playbook uses, run on three localhost
// connections: one newer than the manager, one compatible, one with no agent.
func realMarkers(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/ansible-debug-markers.txt")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestParseObservationReadsARealCapture(t *testing.T) {
	obs, err := ParseObservation(realMarkers(t))
	if err != nil {
		t.Fatal(err)
	}
	if obs.ManagerHost != "mgr-1" || obs.ManagerVersion != "4.14.1" {
		t.Fatalf("manager = %s %s", obs.ManagerHost, obs.ManagerVersion)
	}
	want := map[string]HostState{
		"agent-new":  {Host: "agent-new", Installed: "4.14.9-1", Skewed: true, Registration: "003:agent-new"},
		"agent-ok":   {Host: "agent-ok", Installed: "4.14.1-1", Registration: "002:agent-ok"},
		"agent-none": {Host: "agent-none"},
	}
	if len(obs.Hosts) != len(want) {
		t.Fatalf("hosts = %+v", obs.Hosts)
	}
	for _, h := range obs.Hosts {
		if !reflect.DeepEqual(h, want[h.Host]) {
			t.Errorf("%s = %+v, want %+v", h.Host, h, want[h.Host])
		}
	}
	if got := obs.SkewedHosts(); !reflect.DeepEqual(got, []string{"agent-new"}) {
		t.Errorf("SkewedHosts = %v", got)
	}
}

func TestParseObservationIgnoresAnsiColor(t *testing.T) {
	colored := strings.ReplaceAll(realMarkers(t), "ok: [", "\x1b[0;32mok: [")
	if _, err := ParseObservation(colored); err != nil {
		t.Fatal(err)
	}
}

// Every refusal below is a run that must NOT read as "nothing to do".
func TestParseObservationRefusesAmbiguousRuns(t *testing.T) {
	good := realMarkers(t)
	cases := map[string]string{
		"no manager line":      strings.ReplaceAll(good, "PILOT_HOTFIX_MANAGER", "PILOT_HOTFIX_MGR"),
		"no host judged":       strings.ReplaceAll(good, "PILOT_HOTFIX_STATE", "PILOT_HOTFIX_STAT"),
		"empty output":         "",
		"two managers":         good + "\"PILOT_HOTFIX_MANAGER host=mgr-2 version=4.14.1\"\n",
		"one manager two vers": good + "\"PILOT_HOTFIX_MANAGER host=mgr-1 version=4.14.9\"\n",
		"host reported twice differently": good +
			"\"PILOT_HOTFIX_STATE host=agent-ok installed=4.14.9-1 skewed=true registration=002:agent-ok\"\n",
		"newer but nothing installed": strings.ReplaceAll(good,
			"host=agent-none installed=none skewed=false", "host=agent-none installed=none skewed=true"),
	}
	for name, out := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseObservation(out); err == nil {
				t.Fatal("expected a refusal")
			}
		})
	}
}

func TestParseObservationAcceptsTheSameHostTwiceWhenItAgrees(t *testing.T) {
	obs, err := ParseObservation(realMarkers(t) +
		"\"PILOT_HOTFIX_STATE host=agent-ok installed=4.14.1-1 skewed=false registration=002:agent-ok\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Hosts) != 3 {
		t.Fatalf("hosts = %d, want 3", len(obs.Hosts))
	}
}

func TestParseResults(t *testing.T) {
	got := ParseResults(realMarkers(t))
	want := []Result{{Host: "agent-new", Outcome: OutcomeRemoved, Registration: "003:agent-new"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("results = %+v", got)
	}
}

func TestRenderPlanSaysWhatWillAndWillNotHappen(t *testing.T) {
	obs, err := ParseObservation(realMarkers(t))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	obs.RenderPlan(&buf)
	text := buf.String()
	for _, want := range []string{"mgr-1", "4.14.1", "agent-new", "4.14.9-1", "移除 agent 並在 manager 取消登記", "不動（版本相容）", "（未安裝）"} {
		if !strings.Contains(text, want) {
			t.Errorf("plan lacks %q:\n%s", want, text)
		}
	}
	// A compatible host must never be described as removed.
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "agent-ok") && strings.Contains(line, "移除") {
			t.Errorf("a compatible host is shown as removed: %q", line)
		}
	}
}

func obsOf(hosts ...HostState) Observation {
	return Observation{ManagerHost: "m", ManagerVersion: "4.14.1", Hosts: hosts}
}

func TestSummarizeSuccessComesOnlyFromReportedRemovals(t *testing.T) {
	newer := HostState{Host: "a", Installed: "4.14.9-1", Skewed: true, Registration: "001:a"}
	ok := HostState{Host: "b", Installed: "4.14.1-1"}
	plan := obsOf(newer, ok)

	t.Run("removed", func(t *testing.T) {
		s := Summarize(plan, plan, []Result{{Host: "a", Outcome: OutcomeRemoved}})
		if !reflect.DeepEqual(s.Removed, []string{"a"}) || !reflect.DeepEqual(s.Compatible, []string{"b"}) || len(s.Incomplete) != 0 {
			t.Fatalf("%+v", s)
		}
	})
	t.Run("planned but never reported removed is incomplete", func(t *testing.T) {
		s := Summarize(plan, plan, nil)
		if !reflect.DeepEqual(s.Incomplete, []string{"a"}) || len(s.Removed) != 0 {
			t.Fatalf("%+v", s)
		}
	})
	t.Run("would-remove (check mode) is not a removal", func(t *testing.T) {
		s := Summarize(plan, plan, []Result{{Host: "a", Outcome: OutcomeWouldRemove}})
		if !reflect.DeepEqual(s.Incomplete, []string{"a"}) {
			t.Fatalf("%+v", s)
		}
	})
	t.Run("a planned host the apply run never judged is incomplete", func(t *testing.T) {
		s := Summarize(plan, obsOf(ok), nil)
		if !reflect.DeepEqual(s.Incomplete, []string{"a"}) {
			t.Fatalf("%+v", s)
		}
	})
	t.Run("a planned host that became compatible is not a failure", func(t *testing.T) {
		healed := HostState{Host: "a", Installed: "4.14.1-1"}
		s := Summarize(plan, obsOf(healed, ok), nil)
		if len(s.Incomplete) != 0 || !reflect.DeepEqual(s.Compatible, []string{"a", "b"}) {
			t.Fatalf("%+v", s)
		}
	})
	t.Run("a host that turned newer after the plan is reported", func(t *testing.T) {
		late := HostState{Host: "c", Installed: "4.14.9-1", Skewed: true}
		s := Summarize(plan, obsOf(newer, ok, late), []Result{{Host: "a", Outcome: OutcomeRemoved}, {Host: "c", Outcome: OutcomeRemoved}})
		if !reflect.DeepEqual(s.UnexpectedNew, []string{"c"}) || !reflect.DeepEqual(s.Removed, []string{"a", "c"}) {
			t.Fatalf("%+v", s)
		}
	})
}

// ansible-failed-typed-refusal.txt is the real fatal line ansible-playbook printed when the helper
// refused a host (a Wazuh writer was active); only the VM's address is replaced.
func TestRefusalsReadsTheTypedReasonOutOfARealFailedTask(t *testing.T) {
	data, err := os.ReadFile("testdata/ansible-failed-typed-refusal.txt")
	if err != nil {
		t.Fatal(err)
	}
	got := Refusals(string(data))
	want := []string{"a Wazuh writer or unfinished transaction is active on this host (writer-active.json); recover or finish it before the hotfix"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Refusals = %q, want %q", got, want)
	}
	// the same reason printed twice (two hosts) is listed once; a failure with no typed reason lists none
	if got := Refusals(string(data) + string(data)); len(got) != 1 {
		t.Errorf("repeats = %q", got)
	}
	if got := Refusals(`fatal: [h]: FAILED! => {"msg": "non-zero return code", "rc": 2}`); len(got) != 0 {
		t.Errorf("a failure with no typed reason = %q", got)
	}
}
