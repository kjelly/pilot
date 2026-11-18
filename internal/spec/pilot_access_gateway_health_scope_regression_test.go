package spec

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

// A from-scratch site-wide deploy installs pilot-access-gateway on a host whose
// FreeIPA server is built earlier in the same run. The hostgroup
// pilot-target-<scope> is published afterwards by the day-2
// `pilot gateway-scope reconcile` (which needs that server), and its ownership
// ledger refuses a hostgroup created any other way. Step 17 required
// `status: ok` and Step 18 the hostgroup, so the first apply always stopped
// there with a 503 (minimal-PoC 5-node clean-room acceptance, bastion,
// 2026-11-12). These tests run the real Step 17/18 tasks on localhost and lock
// the rule that replaced it: a gateway that will not install ForceCommand
// accepts exactly one degraded shape, every other answer still stops the run,
// and a gateway that will install ForceCommand stays strict.

// Health bodies: okBody and the unreachable body follow handleHealth in
// internal/gatewayapi/routes.go; scopeMissingBody is the answer captured from
// the real gateway on the failed first apply.
const (
	okBody = `{"status":"ok","gateway_id":"gw","gateway_scope":"all","target_hostgroup":"pilot-target-all",` +
		`"freeipa":"reachable","target_scope":"ok","credential":"ok"}`
	scopeMissingBody = `{"status":"degraded","freeipa":"reachable","credential":"ok","target_scope":"missing","target_hostgroup":"pilot-target-all"}`
	ipaDownBody      = `{"status":"degraded","gateway_id":"gw","gateway_scope":"all","target_hostgroup":"pilot-target-all",` +
		`"freeipa":"unreachable","target_scope":"missing","credential":"unknown"}`
	credentialBadBody = `{"status":"degraded","freeipa":"reachable","credential":"unknown","target_scope":"missing","target_hostgroup":"pilot-target-all"}`
)

const (
	probeTask      = "Step 17: capability probe FreeIPA via /v1/health"
	gateTask       = "Step 17: gate — health probe reports ok"
	warn17Task     = "Step 17: pilot-target-<scope> is not published yet (ForceCommand not requested)"
	assert18Task   = "Step 18: verify configured pilot-target-<scope> exists"
	warn18Task     = "Step 18: pilot-target-<scope> is not published yet (ForceCommand not requested)"
	curlConnectErr = `echo 'curl: (7) Failed to connect' >&2; exit 7`
)

func TestRegression_GatewayFirstApplyAcceptsOnlyAMissingScope(t *testing.T) {
	pb := fcPlaybooks[0]
	playVars, tasks := fcPlay(t, pb)
	want := []string{probeTask, gateTask, warn17Task, assert18Task, warn18Task}
	var keep []map[string]any
	for _, name := range want {
		var found map[string]any
		for _, task := range tasks {
			if fcName(task) == name {
				found = task
			}
		}
		if found == nil {
			t.Fatalf("task %q not found in %s", name, pb.path)
		}
		keep = append(keep, found)
	}
	probe := keep[0]
	argv := fmt.Sprint(probe["ansible.builtin.command"])
	if strings.Contains(argv, "--fail") {
		t.Errorf("the probe must not use --fail: a degraded gateway answers 503 and the body is what the rule reads: %s", argv)
	}
	if !strings.Contains(fmt.Sprint(probe["until"]), "gateway_health_acceptable") {
		t.Errorf("the probe must retry until the acceptance rule holds, got until=%v", probe["until"])
	}
	if n, _ := probe["retries"].(int); n < 3 {
		t.Errorf("the probe must keep its retries, got %v", probe["retries"])
	}

	type result struct {
		failedAt string // task name that must fail; empty means the run must pass
		warns    []string
	}
	for _, tc := range []struct {
		name         string
		forcecommand bool
		body         string
		curlFails    bool
		showRC       any // nil: Step 13's result is not defined (tag-scoped run)
		check        bool
		want         result
	}{
		// Must pass.
		{name: "no-forcecommand/healthy/scope-published", body: okBody, showRC: 0},
		{name: "no-forcecommand/healthy/show-says-absent-warns-at-18", body: okBody, showRC: 2,
			want: result{warns: []string{warn18Task}}},
		{name: "no-forcecommand/first-apply-scope-not-published-yet", body: scopeMissingBody, showRC: 2,
			want: result{warns: []string{warn17Task, warn18Task}}},
		{name: "forcecommand/healthy/scope-published", forcecommand: true, body: okBody, showRC: 0},
		{name: "check-mode-skips-every-step", body: scopeMissingBody, showRC: 2, check: true},
		// Must stop the run.
		{name: "no-forcecommand/scope-missing-but-the-group-exists", body: scopeMissingBody, showRC: 0,
			want: result{failedAt: gateTask}},
		{name: "no-forcecommand/scope-missing-and-no-independent-lookup", body: scopeMissingBody,
			want: result{failedAt: gateTask}},
		{name: "no-forcecommand/freeipa-unreachable", body: ipaDownBody, showRC: 2, want: result{failedAt: gateTask}},
		{name: "no-forcecommand/credential-not-ok", body: credentialBadBody, showRC: 2, want: result{failedAt: gateTask}},
		{name: "no-forcecommand/gateway-does-not-answer", curlFails: true, showRC: 2, want: result{failedAt: gateTask}},
		{name: "forcecommand/scope-not-published-stays-fail-closed", forcecommand: true, body: scopeMissingBody, showRC: 2,
			want: result{failedAt: gateTask}},
		{name: "forcecommand/healthy-but-hostgroup-absent", forcecommand: true, body: okBody, showRC: 2,
			want: result{failedAt: assert18Task}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tasks []map[string]any
			if tc.showRC != nil {
				tasks = append(tasks, map[string]any{
					"name":                     "Stand in for Step 13's hostgroup-show result",
					"ansible.builtin.set_fact": map[string]any{"gateway_target_hostgroup_show": map[string]any{"rc": tc.showRC}},
				})
			}
			for _, task := range keep {
				c := fcRewrite(task)
				if fcName(task) == probeTask {
					c["retries"], c["delay"] = 1, 0
				}
				tasks = append(tasks, c)
			}
			health := []any{"printf", "%s", tc.body}
			if tc.curlFails {
				health = []any{"sh", "-c", curlConnectErr}
			}
			extra := map[string]any{
				"fc_health_cmd":                             health,
				"gateway_scope":                             "all",
				"gateway_target_hostgroup":                  "pilot-target-all",
				"gateway_socket_path":                       "/run/pilot/access-gateway.sock",
				"pilot_access_gateway_install_forcecommand": tc.forcecommand,
			}
			var args []string
			if tc.check {
				args = append(args, "--check")
			}
			run := runLocalTasks(t, playVars, tasks, t.TempDir(), extra, args...)
			if tc.want.failedAt == "" {
				if run.rc != 0 {
					t.Fatalf("expected the run to pass, rc=%d failures=%v\n%s", run.rc, run.failures, run.raw)
				}
			} else {
				if run.rc == 0 || len(run.failures) == 0 {
					t.Fatalf("expected %q to stop the run, it passed\n%s", tc.want.failedAt, run.raw)
				}
				if !strings.HasPrefix(run.failures[0], tc.want.failedAt) {
					t.Fatalf("expected the run to stop at %q, got %v", tc.want.failedAt, run.failures)
				}
			}
			for _, w := range []string{warn17Task, warn18Task} {
				wantWarn := false
				for _, name := range tc.want.warns {
					wantWarn = wantWarn || name == w
				}
				if run.ran[w] != wantWarn {
					t.Errorf("task %q ran=%v, want %v", w, run.ran[w], wantWarn)
				}
			}
		})
	}
}

// The ForceCommand install path keeps its own health gate in front of the
// drop-in, so loosening Step 17 for a gateway that does not install it never
// weakens the case that redirects every portal user.
func TestRegression_GatewayForceCommandStillHasItsOwnHealthGate(t *testing.T) {
	raw, err := os.ReadFile(fcPlaybooks[0].path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, must := range []string{
		`"ForceCommand gate: pilot-access-gateway is healthy"`,
		`(gateway_forcecommand_health.stdout | from_json).status == 'ok'`,
	} {
		if !strings.Contains(text, must) {
			t.Errorf("the ForceCommand health gate lost %s", must)
		}
	}
}

// step13Task is the task whose result Step 17's acceptance rule reads (through
// gateway_target_hostgroup_show) and that Step 18 gates on.
const step13Task = "Step 13: resolve current pilot-target-<scope> membership (existence check)"

// gatewayNestedTaskTags returns the tags a named task of the gateway play ends up with,
// including the ones it inherits from the blocks around it.
func gatewayNestedTaskTags(t *testing.T, tasks []map[string]any, name string) []string {
	t.Helper()
	var tags []string
	found := false
	walkTaskTree(fcTaskList(tasks), nil, func(task map[string]any, own []string) {
		if fcName(task) == name {
			tags, found = own, true
		}
	})
	if !found {
		t.Fatalf("task %q not found in %s", name, fcPlaybooks[0].path)
	}
	return tags
}

// AG06 is "FreeIPA reachable via /v1/health", and Step 17's probe carries it.
// The probe cannot fail on its own any more (failed_when: false, so that the
// acceptance decision can read a degraded gateway's 503 body), which makes the
// gate after it the only task that can report a gateway that is down. A
// `--tags AG06` run (what pilot deploy's tags prompt produces for one row)
// that selected the probe but not the gate passed against a dead gateway
// (round-34 review, F-1). Every task that reads the probe result therefore
// carries every tag the probe carries.
func TestRegression_GatewayHealthReadersCarryTheProbeTags(t *testing.T) {
	_, tasks := fcPlay(t, fcPlaybooks[0])
	probeTags := gatewayNestedTaskTags(t, tasks, probeTask)
	if !slices.Contains(probeTags, "AG06") {
		t.Fatalf("the probe lost its row tag AG06: %v", probeTags)
	}
	readers := 0
	walkTaskTree(fcTaskList(tasks), nil, func(task map[string]any, tags []string) {
		name := fcName(task)
		if name == probeTask || task["block"] != nil {
			return
		}
		body := fmt.Sprint(task)
		if !strings.Contains(body, "gateway_health_probe") && !strings.Contains(body, "gateway_health_acceptable") {
			return
		}
		readers++
		if missing := missingFCTags(tags, probeTags); len(missing) > 0 {
			t.Errorf("%q reads the health probe result but lacks %v, so a run that selects the probe by that tag skips it (tags %v)",
				name, missing, tags)
		}
	})
	if readers < 2 {
		t.Errorf("found %d tasks reading the health probe besides the probe, want at least the gate and the not-published-yet notice", readers)
	}
}

// The same rule by behaviour: run the real Step 17 tasks selected by the tags of
// the probe's row, the way ansible-playbook --tags AG06 selects them. A dead
// gateway and every degraded answer outside the one acceptable first-apply
// shape must stop the run; the healthy answer and the acceptable first-apply
// shape must not. Step 13 (the independent hostgroup lookup, tags AG_config,
// AG_service, AG12) is stood in for with its real tags, so `--tags AG06` alone
// has no lookup result (the rule then stays strict, as its comment says) and
// `--tags AG06,AG12` has one.
func TestRegression_GatewayAG06RowTagReportsAFailingGateway(t *testing.T) {
	playVars, tasks := fcPlay(t, fcPlaybooks[0])
	var keep []map[string]any
	for _, name := range []string{probeTask, gateTask, warn17Task} {
		var found map[string]any
		for _, task := range tasks {
			if fcName(task) == name {
				found = task
			}
		}
		if found == nil {
			t.Fatalf("task %q not found in %s", name, fcPlaybooks[0].path)
		}
		c := fcRewrite(found)
		if name == probeTask {
			c["retries"], c["delay"] = 1, 0
		}
		keep = append(keep, c)
	}
	step13Tags := gatewayNestedTaskTags(t, tasks, step13Task)
	if !slices.Contains(step13Tags, "AG12") {
		t.Fatalf("%q lost its AG12 tag: %v", step13Task, step13Tags)
	}
	garbageBody := `<html><body>502 Bad Gateway</body></html>`
	scopeOKDegradedBody := `{"status":"degraded","freeipa":"reachable","credential":"ok","target_scope":"ok","target_hostgroup":"pilot-target-all"}`

	for _, tc := range []struct {
		name         string
		tags         string
		forcecommand bool
		body         string
		curlFails    bool
		showRC       any // nil: Step 13's result is not defined
		failedAt     string
		warns        bool // the "not published yet" notice runs
	}{
		// A run selected by the probe's row tag must be able to report the failure.
		{name: "AG06/gateway-does-not-answer", tags: "AG06", curlFails: true, failedAt: gateTask},
		{name: "AG06/gateway-does-not-answer/forcecommand", tags: "AG06", forcecommand: true, curlFails: true, failedAt: gateTask},
		{name: "AG06/freeipa-unreachable", tags: "AG06", body: ipaDownBody, failedAt: gateTask},
		{name: "AG06/credential-not-ok", tags: "AG06", body: credentialBadBody, failedAt: gateTask},
		{name: "AG06/degraded-with-a-scope-that-is-fine", tags: "AG06", body: scopeOKDegradedBody, failedAt: gateTask},
		{name: "AG06/answer-is-not-json", tags: "AG06", body: garbageBody, failedAt: gateTask},
		{name: "AG06/forcecommand/scope-missing", tags: "AG06", forcecommand: true, body: scopeMissingBody, failedAt: gateTask},
		{name: "AG06/first-apply-shape-without-step13-lookup-stays-strict", tags: "AG06", body: scopeMissingBody, failedAt: gateTask},
		// And must not fail a gateway that is fine or in the one acceptable state.
		{name: "AG06/healthy", tags: "AG06", body: okBody},
		{name: "AG06/healthy/forcecommand", tags: "AG06", forcecommand: true, body: okBody},
		{name: "AG06+AG12/first-apply-scope-not-published-yet", tags: "AG06,AG12", body: scopeMissingBody, showRC: 2, warns: true},
		{name: "AG06+AG12/scope-missing-but-the-group-exists", tags: "AG06,AG12", body: scopeMissingBody, showRC: 0, failedAt: gateTask},
		{name: "AG06+AG12/forcecommand/first-apply-shape-stays-strict", tags: "AG06,AG12", forcecommand: true, body: scopeMissingBody, showRC: 2,
			failedAt: gateTask},
		{name: "AG06+AG12/gateway-does-not-answer", tags: "AG06,AG12", curlFails: true, showRC: 2, failedAt: gateTask},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var run []map[string]any
			if tc.showRC != nil {
				run = append(run, map[string]any{
					"name":                     "Stand in for Step 13's hostgroup-show result",
					"ansible.builtin.set_fact": map[string]any{"gateway_target_hostgroup_show": map[string]any{"rc": tc.showRC}},
					"tags":                     step13Tags,
				})
			}
			run = append(run, keep...)
			health := []any{"printf", "%s", tc.body}
			if tc.curlFails {
				health = []any{"sh", "-c", curlConnectErr}
			}
			extra := map[string]any{
				"fc_health_cmd":                             health,
				"gateway_scope":                             "all",
				"gateway_target_hostgroup":                  "pilot-target-all",
				"gateway_socket_path":                       "/run/pilot/access-gateway.sock",
				"pilot_access_gateway_install_forcecommand": tc.forcecommand,
			}
			res := runLocalTasks(t, playVars, run, t.TempDir(), extra, "--tags", tc.tags)
			if !res.ran[probeTask] {
				t.Fatalf("--tags %s did not select the probe, the case tests nothing\n%s", tc.tags, res.raw)
			}
			if tc.failedAt == "" {
				if res.rc != 0 || len(res.failures) != 0 {
					t.Fatalf("expected the run to pass, rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
				}
			} else {
				if res.rc == 0 || len(res.failures) == 0 {
					t.Fatalf("--tags %s passed although %q must stop the run\n%s", tc.tags, tc.failedAt, res.raw)
				}
				if !strings.HasPrefix(res.failures[0], tc.failedAt) {
					t.Fatalf("expected the run to stop at %q, got %v", tc.failedAt, res.failures)
				}
			}
			if res.ran[warn17Task] != tc.warns {
				t.Errorf("task %q ran=%v, want %v", warn17Task, res.ran[warn17Task], tc.warns)
			}
		})
	}
}
