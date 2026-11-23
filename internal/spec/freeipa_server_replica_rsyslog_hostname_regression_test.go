package spec

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// Minimal-PoC round 32, finding F3 (kjelly/pilot#343): rsyslog stamps every
// message with the hostname it read when it started, so a replica whose log
// forwarding was set up before freeipa-server-replica-apply.yml renamed it kept
// logging under its old name. The playbook now checks the effective state, not
// whether the hostname task changed: a probe task compares rsyslog's
// ActiveEnterTimestamp with the mtime of /etc/hostname, and a second task
// restarts rsyslog only when the probe says "stale". The existing tests only
// read the YAML. This one runs both real tasks (found by name, so a rename
// fails the test) on localhost with real ansible-playbook, and decides by what
// the run did: how many times systemctl was told to restart rsyslog and what
// each task reported.
//
// Never run here: the hostname task, a real systemctl, the real /etc/hostname.
// systemctl and stat are test doubles first on the PATH the play gives its tasks
// (`environment:`), which is also the PATH the systemd module finds systemctl on.
// The doubles follow what the real commands print, captured on 2026-11-19 on a
// development host (Ubuntu 26.04, systemd 259) with TZ=UTC:
//
//	systemctl show systemd-journald -p ActiveEnterTimestamp --value
//	    Mon 2026-11-09 01:37:45 UTC
//	systemctl is-active --quiet <stopped unit>   -> exit 3
//	systemctl is-active --quiet <unknown unit>   -> exit 4
//
// A host whose timezone abbreviation GNU date cannot read (the same command
// prints "... CST" under TZ=Asia/Taipei) is a different defect, filed as
// kjelly/pilot#408; the environment here pins TZ=UTC and no case locks the
// behaviour under CST.
//
// `make site-day2-roles-test` runs this with PILOT_REQUIRE_CONTAINER_TESTS=1 (the
// target's -run regex is a prefix of this test's name; the last test below keeps
// it that way), so a missing ansible-playbook fails there instead of skipping.

const (
	replicaRsyslogPlaybook    = "freeipa-server-replica-apply.yml"
	replicaRsyslogProbeTask   = "FreeIPA replica — is rsyslog older than the hostname it was started under?"
	replicaRsyslogRestartTask = "FreeIPA replica — restart rsyslog so its log label follows the new hostname"
	replicaRsyslogTestName    = "TestRegression_SiteDay2RolesReplicaRsyslogFollowsTheHostname"
)

// replicaRsyslogFakeSystemctl answers like systemd for one unit, rsyslog, whose
// state is in $F3_DIR/state (active, stopped = a known unit that is not running,
// unknown = no such unit) and whose start time is in $F3_DIR/started. Every call
// is appended to $F3_DIR/calls. A restart makes it active and stamps now.
const replicaRsyslogFakeSystemctl = `#!/bin/sh
d="$F3_DIR"
printf '%s\n' "$*" >> "$d/calls"
state=$(cat "$d/state")
case "$1" in
  is-active)
    case "$state" in active) exit 0 ;; stopped) exit 3 ;; *) exit 4 ;; esac ;;
  show)
    case "$*" in
      *ActiveEnterTimestamp*) cat "$d/started" ;;
      *) printf 'Id=rsyslog.service\nLoadState=loaded\nActiveState=%s\nSubState=running\nUnitFileState=enabled\n' "$state" ;;
    esac ;;
  restart)
    echo active > "$d/state"
    TZ=UTC date '+%a %Y-%m-%d %H:%M:%S UTC' > "$d/started" ;;
  *) echo "unexpected systemctl call: $*" >&2; exit 9 ;;
esac
`

// replicaRsyslogFakeStat answers the one stat call the probe makes,
// `stat -c %Y /etc/hostname`, from a file in the test's temp directory (the
// real stat, REAL_STAT, so the mtime is the real thing), and refuses every other
// call.
const replicaRsyslogFakeStat = `#!/bin/sh
printf 'stat %s\n' "$*" >> "$F3_DIR/calls"
if [ "$1" = -c ] && [ "$2" = %Y ] && [ "$3" = /etc/hostname ]; then exec REAL_STAT -c %Y "$F3_DIR/hostname"; fi
echo "unexpected stat call: $*" >&2
exit 9
`

// replicaRsyslogHost is one scripted host: a hostname file whose mtime is
// hostnameMTime and a fake rsyslog.
type replicaRsyslogHost struct {
	dir           string
	bin           string
	hostnameMTime time.Time
}

// newReplicaRsyslogHost builds the doubles. unit is "active", "stopped" or
// "unknown"; started says when an active rsyslog started relative to the
// hostname change: "stale" (an hour before it) or "current" (an hour after).
func newReplicaRsyslogHost(t *testing.T, unit, started string) *replicaRsyslogHost {
	t.Helper()
	realStat, err := exec.LookPath("stat")
	if err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatalf("stat not installed: %v (PILOT_REQUIRE_CONTAINER_TESTS=1)", err)
		}
		t.Skipf("stat not installed: %v", err)
	}
	h := &replicaRsyslogHost{dir: t.TempDir(), hostnameMTime: time.Now().Add(-3 * time.Hour).Truncate(time.Second)}
	h.bin = filepath.Join(h.dir, "bin")
	if err := os.Mkdir(h.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"systemctl": replicaRsyslogFakeSystemctl,
		"stat":      strings.Replace(replicaRsyslogFakeStat, "REAL_STAT", realStat, 1),
	} {
		if err := os.WriteFile(filepath.Join(h.bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	hostname := filepath.Join(h.dir, "hostname")
	if err := os.WriteFile(hostname, []byte("ipa2.example.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(hostname, h.hostnameMTime, h.hostnameMTime); err != nil {
		t.Fatal(err)
	}
	startedAt := h.hostnameMTime.Add(-time.Hour)
	if started == "current" {
		startedAt = h.hostnameMTime.Add(time.Hour)
	}
	files := map[string]string{
		"state":   unit + "\n",
		"started": startedAt.UTC().Format("Mon 2006-01-02 15:04:05 UTC") + "\n",
		"calls":   "",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(h.dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

// replicaRsyslogTask is what one task reported on localhost.
type replicaRsyslogTask struct {
	Name    string
	Changed bool
	Skipped bool
	Failed  bool
	Stdout  string
	Msg     string
}

// replicaRsyslogRun is one ansible-playbook run of the two real tasks.
type replicaRsyslogRun struct {
	probe, restart replicaRsyslogTask
	// restarts is how many times systemctl was told to restart rsyslog during
	// this run; calls is every systemctl and stat call it made.
	restarts int
	calls    []string
}

// readCalls returns the calls logged so far and truncates the log, so each run
// sees only its own.
func (h *replicaRsyslogHost) readCalls(t *testing.T) []string {
	t.Helper()
	path := filepath.Join(h.dir, "calls")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var calls []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line != "" {
			calls = append(calls, line)
		}
	}
	return calls
}

// run plays the real probe and restart tasks (by name, from the real playbook)
// on localhost with ansible-playbook and the given extra arguments.
func (h *replicaRsyslogHost) run(t *testing.T, args ...string) replicaRsyslogRun {
	t.Helper()
	playbook := loadYAML(t, filepath.Join("..", "..", "playbooks", "apply", replicaRsyslogPlaybook))
	play := []map[string]any{{
		"name": "replica rsyslog", "hosts": "localhost", "gather_facts": false, "become": false,
		"environment": map[string]any{
			"PATH":   h.bin + string(os.PathListSeparator) + os.Getenv("PATH"),
			"TZ":     "UTC",
			"LC_ALL": "C",
			"F3_DIR": h.dir,
		},
		"tasks": []any{
			findNamedTask(t, playbook, replicaRsyslogProbeTask),
			findNamedTask(t, playbook, replicaRsyslogRestartTask),
		},
	}}
	work := t.TempDir()
	write := func(name string, v any) string {
		body, err := yaml.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(work, name)
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	inv := write("inventory.yml", map[string]any{"all": map[string]any{"hosts": map[string]any{"localhost": localHostVars()}}})
	cmd := exec.Command("ansible-playbook", append([]string{"-i", inv, write("play.yml", play)}, args...)...)
	cmd.Dir = work
	cmd.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=json", "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False")
	out, runErr := cmd.Output()
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			t.Fatalf("ansible-playbook did not run: %v", runErr)
		}
	}
	var cb struct {
		Plays []struct {
			Tasks []struct {
				Task  struct{ Name string } `json:"task"`
				Hosts map[string]struct {
					Changed bool        `json:"changed"`
					Skipped bool        `json:"skipped"`
					Failed  bool        `json:"failed"`
					Stdout  string      `json:"stdout"`
					Msg     callbackMsg `json:"msg"`
				} `json:"hosts"`
			} `json:"tasks"`
		} `json:"plays"`
	}
	if err := json.Unmarshal(out, &cb); err != nil {
		t.Fatalf("parse JSON callback output: %v\n%s", err, out)
	}
	var tasks []replicaRsyslogTask
	for _, p := range cb.Plays {
		for _, task := range p.Tasks {
			res, ok := task.Hosts["localhost"]
			if !ok {
				t.Fatalf("task %q has no result on localhost", task.Task.Name)
			}
			tasks = append(tasks, replicaRsyslogTask{Name: task.Task.Name, Changed: res.Changed, Skipped: res.Skipped, Failed: res.Failed, Stdout: strings.TrimSpace(res.Stdout), Msg: string(res.Msg)})
		}
	}
	// Exactly the two tasks ran: no hostname task, no fact gathering.
	if len(tasks) != 2 || tasks[0].Name != replicaRsyslogProbeTask || tasks[1].Name != replicaRsyslogRestartTask {
		t.Fatalf("ansible-playbook ran %+v, want the probe and the restart task only\n%s", tasks, out)
	}
	r := replicaRsyslogRun{probe: tasks[0], restart: tasks[1], calls: h.readCalls(t)}
	for _, c := range r.calls {
		if strings.HasPrefix(c, "restart") {
			r.restarts++
		}
	}
	for _, task := range tasks {
		if task.Failed {
			t.Fatalf("task %q failed: %s (calls %q)", task.Name, task.Msg, r.calls)
		}
	}
	return r
}

// started returns the start time the fake rsyslog reports.
func (h *replicaRsyslogHost) started(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(h.dir, "started"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

func TestRegression_SiteDay2RolesReplicaRsyslogFollowsTheHostname(t *testing.T) {
	if t.Name() != replicaRsyslogTestName {
		t.Fatalf("this test is %q but replicaRsyslogTestName says %q: keep them equal so the Makefile check below names the right test", t.Name(), replicaRsyslogTestName)
	}
	requireAnsibleForReplicaGates(t)

	// want is what a run must do: the probe's answer (the probe must have run, not
	// been skipped), the number of restart calls systemctl saw, and whether the
	// restart task reports changed.
	type want struct {
		probe    string
		restarts int
		changed  bool // the restart task reports changed
	}
	check := func(t *testing.T, got replicaRsyslogRun, w want) {
		t.Helper()
		if got.probe.Skipped || got.probe.Stdout != w.probe {
			t.Errorf("probe answered %q (skipped=%v), want %q; calls %q", got.probe.Stdout, got.probe.Skipped, w.probe, got.calls)
		}
		if got.probe.Changed {
			t.Errorf("the probe reported changed: a read-only check must not (idempotency)")
		}
		if got.restarts != w.restarts {
			t.Errorf("systemctl was told to restart rsyslog %d times, want %d; calls %q", got.restarts, w.restarts, got.calls)
		}
		if got.restart.Changed != w.changed {
			t.Errorf("restart task changed=%v, want %v (skipped=%v)", got.restart.Changed, w.changed, got.restart.Skipped)
		}
		if !w.changed && !got.restart.Skipped {
			t.Errorf("restart task ran when nothing needed restarting: %+v", got.restart)
		}
	}

	t.Run("stale rsyslog is restarted once and the rerun changes nothing", func(t *testing.T) {
		h := newReplicaRsyslogHost(t, "active", "stale")
		before := h.started(t)
		check(t, h.run(t), want{probe: "stale", restarts: 1, changed: true})
		if after := h.started(t); after == before {
			t.Errorf("rsyslog start time is still %q after the restart", after)
		}
		// The restarted rsyslog is newer than /etc/hostname: effective state, so
		// the second run does not restart it again.
		check(t, h.run(t), want{probe: "current", restarts: 0})
	})
	t.Run("rsyslog started after the hostname change is left alone", func(t *testing.T) {
		h := newReplicaRsyslogHost(t, "active", "current")
		check(t, h.run(t), want{probe: "current"})
	})
	t.Run("a stopped rsyslog is not started or restarted", func(t *testing.T) {
		h := newReplicaRsyslogHost(t, "stopped", "stale")
		check(t, h.run(t), want{probe: "not-running"})
	})
	t.Run("a host without rsyslog is not touched", func(t *testing.T) {
		h := newReplicaRsyslogHost(t, "unknown", "stale")
		check(t, h.run(t), want{probe: "not-running"})
	})
	t.Run("--check with a stale rsyslog still runs the probe and reports the restart without doing it", func(t *testing.T) {
		h := newReplicaRsyslogHost(t, "active", "stale")
		before := h.started(t)
		check(t, h.run(t, "--check"), want{probe: "stale", restarts: 0, changed: true})
		if after := h.started(t); after != before {
			t.Errorf("--check changed rsyslog's start time from %q to %q", before, after)
		}
	})
	t.Run("--check with a current rsyslog reports no change", func(t *testing.T) {
		h := newReplicaRsyslogHost(t, "active", "current")
		check(t, h.run(t, "--check"), want{probe: "current"})
	})
	t.Run("--tags R1 with a stale rsyslog restarts it", func(t *testing.T) {
		h := newReplicaRsyslogHost(t, "active", "stale")
		check(t, h.run(t, "--tags", "R1"), want{probe: "stale", restarts: 1, changed: true})
	})
}

// The test above only runs under `make site-day2-roles-test` if that target's
// -run regex selects it; a narrower regex would drop it from CI without a
// failure anywhere. Read the regex from the Makefile and apply it to this
// test's name.
func TestRegression_SiteDay2RolesReplicaRsyslogTestIsInTheMakeTarget(t *testing.T) {
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^site-day2-roles-test:.*\n\tPILOT_REQUIRE_CONTAINER_TESTS=1 go test .* -run '([^']+)' \./internal/spec/`).FindSubmatch(makefile)
	if m == nil {
		t.Fatal("Makefile: no site-day2-roles-test target that runs ./internal/spec/ with PILOT_REQUIRE_CONTAINER_TESTS=1")
	}
	// make reads $$ as a literal $.
	pattern := strings.ReplaceAll(string(m[1]), "$$", "$")
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("site-day2-roles-test -run %q: %v", pattern, err)
	}
	if !re.MatchString(replicaRsyslogTestName) {
		t.Errorf("make site-day2-roles-test -run %q does not select %s, so CI would never run it", pattern, replicaRsyslogTestName)
	}
}
