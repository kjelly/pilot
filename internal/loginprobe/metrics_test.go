package loginprobe

import (
	"strings"
	"testing"
	"time"
)

func TestMetrics_PreseedsEveryTargetAndStageAtZero(t *testing.T) {
	m := NewMetrics([]Target{{Name: "a", Host: "a.x", Port: 22}})
	out := m.Registry.Render()
	for _, want := range []string{
		`pilot_login_probe_success{probe_target="a"} 0`,
		`pilot_login_probe_last_success_timestamp_seconds{probe_target="a"} 0`,
		`pilot_login_probe_attempts_total{probe_target="a"} 0`,
		`pilot_login_probe_targets 1`,
		`pilot_login_probe_rounds_total 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	for _, s := range AllStages {
		if !strings.Contains(out, `pilot_login_probe_last_stage{probe_target="a",stage="`+string(s)+`"} 0`) {
			t.Errorf("last_stage for %s not pre-seeded", s)
		}
	}
	for _, s := range FailureStages {
		if !strings.Contains(out, `pilot_login_probe_failures_total{probe_target="a",stage="`+string(s)+`"} 0`) {
			t.Errorf("failures_total for %s not pre-seeded", s)
		}
	}
	if strings.Contains(out, `failures_total{probe_target="a",stage="ok"}`) {
		t.Error("ok must not be a failure stage")
	}
}

func TestMetrics_ObserveFlipsExactlyOneStageAndTracksSuccess(t *testing.T) {
	tg := Target{Name: "a", Host: "a.x", Port: 22}
	m := NewMetrics([]Target{tg})
	at := time.Unix(1_700_000_000, 0)
	m.Observe(Outcome{Target: tg, Stage: StageAccount, ExitCode: 255, Duration: 1500 * time.Millisecond, At: at})
	out := m.Registry.Render()
	for _, want := range []string{
		`pilot_login_probe_success{probe_target="a"} 0`,
		`pilot_login_probe_last_stage{probe_target="a",stage="account"} 1`,
		`pilot_login_probe_last_stage{probe_target="a",stage="ok"} 0`,
		`pilot_login_probe_failures_total{probe_target="a",stage="account"} 1`,
		`pilot_login_probe_attempts_total{probe_target="a"} 1`,
		`pilot_login_probe_duration_seconds{probe_target="a"} 1.5`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	m.Observe(Outcome{Target: tg, Stage: StageOK, Duration: 200 * time.Millisecond, At: at.Add(time.Minute)})
	out = m.Registry.Render()
	for _, want := range []string{
		`pilot_login_probe_success{probe_target="a"} 1`,
		`pilot_login_probe_last_success_timestamp_seconds{probe_target="a"} 1.70000006e+09`,
		`pilot_login_probe_last_stage{probe_target="a",stage="account"} 0`,
		`pilot_login_probe_last_stage{probe_target="a",stage="ok"} 1`,
		`pilot_login_probe_failures_total{probe_target="a",stage="account"} 1`,
		`pilot_login_probe_attempts_total{probe_target="a"} 2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// Exactly one stage is 1 per target.
	ones := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, `pilot_login_probe_last_stage{probe_target="a"`) && strings.HasSuffix(line, " 1") {
			ones++
		}
	}
	if ones != 1 {
		t.Errorf("last_stage has %d series at 1, want exactly 1", ones)
	}
}

func TestMetrics_NoForbiddenLabelNames(t *testing.T) {
	m := NewMetrics([]Target{{Name: "a", Host: "a.x", Port: 22}})
	out := m.Registry.Render()
	for _, forbidden := range []string{"pilot_host=", "instance=", "job=", "site="} {
		if strings.Contains(out, forbidden) {
			t.Errorf("textfile must not carry the %s label (Prometheus would rename it)", forbidden)
		}
	}
}
