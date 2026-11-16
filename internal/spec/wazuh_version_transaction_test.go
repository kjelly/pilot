package spec

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The Python harnesses below drive the real coordinator, helpers and playbook
// tasks. They need a modern interpreter, PyYAML and ansible-core 2.19 (the
// repo's pinned controller, AGENTS 4.5). A missing prerequisite is a hard
// failure with the fix spelled out: a skipped or silently passing harness would
// leave the controls unrun, and "No module named 'yaml'" halfway through a
// shard is a confusing way to learn that.
const (
	wazuhHarnessMinPythonMinor = 11 // unittest.TestCase.enterContext (3.11); CI's setup-python is pinned to 3.11
	wazuhHarnessAnsibleCore    = "2.19"
)

// wazuhHarnessProbe is the exact interpreter check; it prints one JSON object.
const wazuhHarnessProbe = `import json, sys
import yaml
print(json.dumps({"python": list(sys.version_info[:2]), "yaml": yaml.__version__,
                  "executable": sys.executable, "venv": sys.prefix != sys.base_prefix}))`

type wazuhHarnessTools struct {
	PythonMajor, PythonMinor int
	PyYAML, AnsibleCore      string
	Executable               string
	Venv                     bool // sys.prefix != sys.base_prefix
}

// probeWazuhHarnessTools checks the interpreter, PyYAML and ansible-core found
// through env (python3 and ansible-playbook come from PATH, exactly as the
// harness subprocesses will resolve them).

func probeWazuhHarnessTools(env []string) (wazuhHarnessTools, error) {
	var tools wazuhHarnessTools
	run := func(name string, args ...string) (string, error) {
		// exec.Command resolves names with the parent's PATH, not cmd.Env's: look the
		// tool up in env's PATH, which is what the harness subprocesses will see.
		path, err := lookPathIn(env, name)
		if err != nil {
			return err.Error(), err
		}
		cmd := exec.Command(path, args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	out, err := run("python3", "-c", wazuhHarnessProbe)
	if err != nil {
		if strings.Contains(out, "No module named 'yaml'") {
			return tools, fmt.Errorf("PyYAML is not installed for python3 (%s); install it with `python3 -m pip install pyyaml`", firstLine(out))
		}
		return tools, fmt.Errorf("python3 is unusable for the Wazuh harnesses: %v: %s", err, out)
	}
	var probe struct {
		Python     []int  `json:"python"`
		YAML       string `json:"yaml"`
		Executable string `json:"executable"`
		Venv       bool   `json:"venv"`
	}
	if err := json.Unmarshal([]byte(out), &probe); err != nil || len(probe.Python) != 2 {
		return tools, fmt.Errorf("unreadable python3 probe output %q", out)
	}
	tools.PythonMajor, tools.PythonMinor, tools.PyYAML = probe.Python[0], probe.Python[1], probe.YAML
	tools.Executable, tools.Venv = probe.Executable, probe.Venv
	if tools.PythonMajor != 3 || tools.PythonMinor < wazuhHarnessMinPythonMinor {
		return tools, fmt.Errorf("python3 is %d.%d; the Wazuh harnesses need Python 3.%d or newer",
			tools.PythonMajor, tools.PythonMinor, wazuhHarnessMinPythonMinor)
	}
	out, err = run("ansible-playbook", "--version")
	if err != nil {
		return tools, fmt.Errorf("ansible-playbook is required by the real-Ansible Wazuh harnesses: %v: %s; install it with `python3 -m pip install 'ansible-core==%s.*'`", err, out, wazuhHarnessAnsibleCore)
	}
	match := regexp.MustCompile(`core (\d+\.\d+\.\d+)`).FindStringSubmatch(out)
	if match == nil || !strings.HasPrefix(match[1], wazuhHarnessAnsibleCore+".") {
		found := "no ansible-core version"
		if match != nil {
			found = "ansible-core " + match[1]
		}
		return tools, fmt.Errorf("%s found; the Wazuh harnesses are written against ansible-core %s.x: install `python3 -m pip install 'ansible-core==%s.*'`",
			found, wazuhHarnessAnsibleCore, wazuhHarnessAnsibleCore)
	}
	tools.AnsibleCore = match[1]
	return tools, nil
}

// lookPathIn finds name in the PATH carried by env (the last PATH entry wins,
// as it does for exec.Cmd.Env).

func lookPathIn(env []string, name string) (string, error) {
	paths := ""
	for _, entry := range env {
		if value, ok := strings.CutPrefix(entry, "PATH="); ok {
			paths = value
		}
	}
	for _, dir := range filepath.SplitList(paths) {
		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%s not found on PATH", name)
}

var (
	wazuhToolsOnce sync.Once
	wazuhToolsErr  error
	wazuhTools     wazuhHarnessTools
)

// wazuhHarnessEnv keeps harness runs from writing bytecode into the tree and
// states the hermetic contract: testdata/wazuh_hermetic.py enforces it.

func wazuhHarnessEnv() []string {
	return append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1", "PILOT_WAZUH_HERMETIC=enforce")
}

var wazuhRan = regexp.MustCompile(`(?m)^Ran (\d+) tests? in `)

// wazuhSystemPythonError reports why the interpreter cannot run the harnesses.
// They run the production helpers as ordinary python3 subprocesses next to the
// CI interpreter (setup-python, not a virtual environment): a venv resolves
// modules, site-packages and sys.executable differently, so a result obtained in
// one proves nothing about CI. Without this check a venv shows up as a dozen
// unrelated-looking failures.

func wazuhSystemPythonError(tools wazuhHarnessTools) error {
	if tools.Venv {
		return fmt.Errorf("python3 (%s) is a virtual environment (sys.prefix != sys.base_prefix); the harnesses are qualified on the CI interpreter: put a non-venv Python %d.%d+ first on PATH (PyYAML via PYTHONPATH or `pip install --user`)",
			tools.Executable, tools.PythonMajor, wazuhHarnessMinPythonMinor)
	}
	if !filepath.IsAbs(tools.Executable) {
		return fmt.Errorf("python3 reports a non-absolute sys.executable %q; the harnesses need the running absolute interpreter", tools.Executable)
	}
	return nil
}

// wazuhHarnessReady probes the toolchain once per process and fails the test
// when a prerequisite is missing or the interpreter is a virtual environment.

func wazuhHarnessReady(t *testing.T, what string) wazuhHarnessTools {
	t.Helper()
	wazuhToolsOnce.Do(func() {
		wazuhTools, wazuhToolsErr = probeWazuhHarnessTools(wazuhHarnessEnv())
		if wazuhToolsErr == nil {
			wazuhToolsErr = wazuhSystemPythonError(wazuhTools)
		}
	})
	if wazuhToolsErr != nil {
		t.Fatalf("%s cannot run: %v", what, wazuhToolsErr)
	}
	return wazuhTools
}

// runWazuhHarness runs one Python harness and fails the test on any problem:
// a missing prerequisite, a non-zero exit, a skipped test, or a run that
// executed no test at all.

func runWazuhHarness(t *testing.T, script, what string, extra ...string) {
	t.Helper()
	// The harnesses are independent (private temp trees, own processes): run them
	// alongside each other once the serial tests of the package are done, except the
	// ones whose assertions read shared filesystem state (wazuhSerialHarnesses).
	if !wazuhSerialHarnesses[script] {
		t.Parallel()
	}
	wazuhHarnessReady(t, what)
	for _, tool := range extra {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s cannot run: %s is required: %v", what, tool, err)
		}
	}
	cmd := exec.Command("python3", script)
	cmd.Env = wazuhHarnessEnv()
	output, err := runWazuhHarnessProcess(cmd)
	if err != nil {
		t.Fatalf("%s failed: %v\n%s", what, err, output)
	}
	ran := wazuhRan.FindSubmatch(output)
	if ran == nil {
		t.Fatalf("%s: no unittest summary in the output, so nothing proves it ran:\n%s", what, output)
	}
	count, _ := strconv.Atoi(string(ran[1]))
	if count == 0 {
		t.Fatalf("%s executed zero tests", what)
	}
	if regexp.MustCompile(`(?m)^OK \(.*skipped=`).Match(output) || strings.Contains(string(output), "skipped '") {
		t.Fatalf("%s skipped tests; every control must execute:\n%s", what, output)
	}
	t.Logf("%s: %d tests executed, 0 skipped (python %d.%d, PyYAML %s, ansible-core %s)",
		script, count, wazuhTools.PythonMajor, wazuhTools.PythonMinor, wazuhTools.PyYAML, wazuhTools.AnsibleCore)
}

// wazuhSerialHarnesses must not run alongside other tests: the prestart inspector compares the
// filesystem metadata of every ancestor of its temporary tree, including the shared /tmp, and
// correctly refuses an input that "changed during inspection" when a concurrent test creates
// files there. Relaxing that check would defeat what the harness proves.
var wazuhSerialHarnesses = map[string]bool{"testdata/wazuh_reader_prestart_test.py": true}

// wazuhHarnessSlots bounds how many Python/Ansible harness processes run at once. Each real
// ansible-playbook run has a fixed in-harness timeout, so an oversubscribed machine turns
// speed-ups into spurious timeouts; four matches a hosted CI runner's cores.
var wazuhHarnessSlots = make(chan struct{}, min(4, max(2, runtime.GOMAXPROCS(0))))

func runWazuhHarnessProcess(cmd *exec.Cmd) ([]byte, error) {
	wazuhHarnessSlots <- struct{}{}
	defer func() { <-wazuhHarnessSlots }()
	return cmd.CombinedOutput()
}

var wazuhShardLine = regexp.MustCompile(`(?m)^SHARD (\d+)/(\d+): (\d+) of (\d+) tests$`)

// runWazuhHarnessSharded runs one slow harness as n parallel shards (PILOT_WAZUH_SHARD=i/n,
// see wazuh_hermetic.run_tests) and proves the shards together executed every test: each
// shard reports how many tests it ran of the module's total, and the counts must add up.
func runWazuhHarnessSharded(t *testing.T, script, what string, shards int) {
	t.Helper()
	t.Parallel()
	wazuhHarnessReady(t, what)
	var mu sync.Mutex
	ran, total := 0, -1
	t.Run("shards", func(t *testing.T) {
		for i := 0; i < shards; i++ {
			t.Run(fmt.Sprintf("shard%d", i), func(t *testing.T) {
				t.Parallel()
				cmd := exec.Command("python3", script)
				cmd.Env = append(wazuhHarnessEnv(), fmt.Sprintf("PILOT_WAZUH_SHARD=%d/%d", i, shards))
				output, err := runWazuhHarnessProcess(cmd)
				if err != nil {
					t.Fatalf("%s shard %d/%d failed: %v\n%s", what, i, shards, err, output)
				}
				line := wazuhShardLine.FindSubmatch(output)
				summary := wazuhRan.FindSubmatch(output)
				if line == nil || summary == nil {
					t.Fatalf("%s shard %d/%d: no shard or unittest summary, so nothing proves it ran:\n%s", what, i, shards, output)
				}
				mine, _ := strconv.Atoi(string(line[3]))
				all, _ := strconv.Atoi(string(line[4]))
				count, _ := strconv.Atoi(string(summary[1]))
				if count != mine {
					t.Fatalf("%s shard %d/%d announced %d tests but ran %d", what, i, shards, mine, count)
				}
				if regexp.MustCompile(`(?m)^OK \(.*skipped=`).Match(output) || strings.Contains(string(output), "skipped '") {
					t.Fatalf("%s shard %d/%d skipped tests; every control must execute:\n%s", what, i, shards, output)
				}
				mu.Lock()
				defer mu.Unlock()
				ran += count
				if total >= 0 && total != all {
					t.Errorf("%s shards disagree on the total number of tests: %d vs %d", what, total, all)
				}
				total = all
			})
		}
	})
	if t.Failed() {
		return
	}
	if total <= 0 || ran != total {
		t.Fatalf("%s: the %d shards ran %d tests of %d; a shard dropped tests", what, shards, ran, total)
	}
	t.Logf("%s: %d tests executed across %d parallel shards, 0 skipped", script, ran, shards)
}

// The coordinator harness has explicit boundaries in its module docstring: the
// native commands are modeled, so it proves policy, parsing and ordering of the
// real code, not VM/native package, signature or Docker behavior.

func TestWazuhVersionCoordinatorBehavior(t *testing.T) {
	runWazuhHarness(t, "testdata/wazuh_transaction_test.py", "Wazuh version coordinator behavioral controls")
}

// The production manager gate tasks run unchanged under real Ansible; the
// coordinator's central action runs for real over modeled docker commands.

func TestWazuhManagerGateGraph(t *testing.T) {
	runWazuhHarness(t, "testdata/wazuh_manager_gate_test.py", "real Ansible Wazuh manager version-gate graph")
}

func TestWazuhVersionTransactionBehavior(t *testing.T) {
	runWazuhHarness(t, "testdata/wazuh_transaction_test.py", "Wazuh transaction behavioral controls")
}

func TestAptExactVersionTaskBehavior(t *testing.T) {
	runWazuhHarness(t, "testdata/apt_exact_task_test.py", "real Ansible exact APT task controls")
}

func TestWazuhWriterTaskGraph(t *testing.T) {
	runWazuhHarnessSharded(t, "testdata/wazuh_writer_task_test.py", "real Ansible Wazuh writer/delegation graph", 3)
}

// Exercise the installed script action and its actual shell: splitting a
// rendered command in Python would hide newlines retained by ScriptModule.

func TestWazuhManagerScriptArguments(t *testing.T) {
	runWazuhHarness(t, "testdata/wazuh_manager_script_args_test.py", "real Ansible manager script argument controls")
}

func TestWazuhSelectionTaskGraph(t *testing.T) {
	runWazuhHarnessSharded(t, "testdata/wazuh_selection_task_test.py", "real Ansible Wazuh selection/failure-authority graph", 6)
}

func TestWazuhReaderCustodyBehavior(t *testing.T) {
	runWazuhHarness(t, "testdata/wazuh_reader_test.py", "Wazuh reader custody controls")
}

// Endpoint identity is exercised through the actual shared resolver and
// ScriptModule, with only inventory/transport data supplied by the fixture.

func TestWazuhEndpointBinding(t *testing.T) {
	runWazuhHarness(t, "testdata/wazuh_endpoint_test.py", "Wazuh endpoint binding controls")
}

// A prerequisite that is missing must stop the harness loudly. Each case puts a
// shim first on PATH that behaves like the broken environment and checks the
// probe's message names the fix, so a CI job without PyYAML or the pinned
// ansible-core cannot report a quiet pass.

func TestWazuhRecoveryEntryAuthority(t *testing.T) {
	runWazuhHarness(t, "testdata/wazuh_recovery_entry_test.py", "Wazuh recovery entry authority controls")
}

// Real static filesystem closure and complete native Exec serialization; native
// systemd/start/cache writes remain independently required target evidence.

func TestWazuhReaderPrestartAuthority(t *testing.T) {
	runWazuhHarness(t, "testdata/wazuh_reader_prestart_test.py", "Wazuh prestart authority controls")
}

// Kernel FD EOF does not prove imfile's logical or durable queue handoff.
// Local real proc/files + authenticated reference-C controls remain distinct
// from the required native unit/queue and receiver target qualification.

func TestWazuhReaderLogicalHandoff(t *testing.T) {
	// cc builds the authenticated reference SipHash implementation.
	runWazuhHarness(t, "testdata/wazuh_reader_logical_test.py", "Wazuh logical handoff controls", "cc")
}

// Actual private Ansible copy/file/temp operations and typed preview asset
// validation, with native account/path facts explicitly modeled by the fixture.

func TestWazuhPreviewToolsBehavior(t *testing.T) {
	if err := wazuhSystemPythonError(wazuhHarnessReady(t, "Wazuh preview asset controls")); err != nil {
		t.Fatalf("Wazuh preview asset controls cannot run: %v", err)
	}
	runWazuhHarnessSharded(t, "testdata/wazuh_preview_tools_test.py", "Wazuh preview asset controls", 5)
}

// The always-tagged retained-agent reinstall tasks report changed from what apt
// or dnf did, not literally true (real Ansible over captured/modeled output).

func TestWazuhRetainedReinstallConvergence(t *testing.T) {
	runWazuhHarness(t, "testdata/wazuh_convergence_test.py", "Wazuh retained reinstall convergence controls")
}

// The ordinary EL apply's who-data endpoint ensure runs the real coordinator
// over a temporary /proc and host tree; auditd/systemd/syscheckd reactions are
// declared models (Issue #323).

func TestWazuhWhodataEnsureBehavior(t *testing.T) {
	runWazuhHarness(t, "testdata/wazuh_whodata_ensure_test.py", "Wazuh who-data endpoint ensure controls")
}

// A prerequisite that is missing must stop the harness loudly. Each case puts a
// shim first on PATH that behaves like the broken environment and checks the
// probe's message names the fix, so a CI job without PyYAML or the pinned
// ansible-core cannot report a quiet pass.

func TestWazuhHarnessPrerequisitesFailLoudly(t *testing.T) {
	realPython, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("python3 is required: %v", err)
	}
	realAnsible, ansibleErr := exec.LookPath("ansible-playbook")
	shim := func(t *testing.T, name, body string) []string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(dir+"/"+name, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
		// Last duplicate wins in exec.Cmd.Env, so the shimmed PATH goes last.
		return append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	}
	cases := []struct {
		name, shimName, body, want string
	}{
		{"no PyYAML", "python3", `case "$1" in -c) echo "ModuleNotFoundError: No module named 'yaml'" >&2; exit 1;; esac
exec ` + realPython + ` "$@"`, "PyYAML is not installed"},
		{"python too old", "python3", `case "$1" in -c) echo '{"python":[3,10],"yaml":"6.0"}'; exit 0;; esac
exec ` + realPython + ` "$@"`, "need Python 3.11 or newer"},
		{"no ansible-playbook", "ansible-playbook", `echo "ansible-playbook: command broken" >&2; exit 127`, "ansible-playbook is required"},
		{"wrong ansible-core", "ansible-playbook", `echo "ansible-playbook [core 2.17.4]"`, "ansible-core"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := probeWazuhHarnessTools(shim(t, tc.shimName, tc.body))
			if err == nil {
				t.Fatalf("a harness without %s passed its prerequisite probe", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name the fix (%q)", err, tc.want)
			}
		})
	}
	// Control: the real environment passes, so the shims above are what failed.
	if ansibleErr != nil {
		t.Fatalf("ansible-playbook (%s) is required on PATH: %v", realAnsible, ansibleErr)
	}
	if _, err := probeWazuhHarnessTools(wazuhHarnessEnv()); err != nil {
		t.Fatalf("the actual environment must satisfy the harness prerequisites: %v", err)
	}
}

// The harnesses refuse a virtual-environment interpreter up front, from the
// probe's reported sys.prefix and not from whichever interpreter happens to run
// this test: the shim answers the probe like a venv python (and like a system
// one for the control).

func TestWazuhHarnessNeedsASystemPython(t *testing.T) {
	realAnsible, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Fatalf("ansible-playbook is required on PATH: %v", err)
	}
	probeWith := func(t *testing.T, reply string) wazuhHarnessTools {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(dir+"/python3", []byte("#!/bin/sh\necho '"+reply+"'\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		tools, err := probeWazuhHarnessTools(append(os.Environ(), "PATH="+dir+":"+filepath.Dir(realAnsible)+":"+os.Getenv("PATH")))
		if err != nil {
			t.Fatalf("probe failed: %v", err)
		}
		return tools
	}
	venv := probeWith(t, `{"python":[3,11],"yaml":"6.0","executable":"/work/.venv/bin/python3","venv":true}`)
	err = wazuhSystemPythonError(venv)
	if err == nil || !strings.Contains(err.Error(), "virtual environment") || !strings.Contains(err.Error(), "/work/.venv/bin/python3") {
		t.Fatalf("a venv python passed or the error does not name it: %v", err)
	}
	relative := probeWith(t, `{"python":[3,11],"yaml":"6.0","executable":"python3","venv":false}`)
	if err := wazuhSystemPythonError(relative); err == nil || !strings.Contains(err.Error(), "non-absolute") {
		t.Fatalf("a relative sys.executable passed or is misreported: %v", err)
	}
	system := probeWith(t, `{"python":[3,11],"yaml":"6.0","executable":"/usr/bin/python3","venv":false}`)
	if err := wazuhSystemPythonError(system); err != nil {
		t.Fatalf("a system python was refused: %v", err)
	}
}

// checkWazuhHarnessCI reports whether the Go test job provisions what the
// Wazuh harnesses need before it runs them: a Python at least as new as the
// harness minimum, then PyYAML and the pinned ansible-core, in a step that
// covers the spec shard and comes before `make test-race`.

func TestWazuhPreviewHarnessNeedsASystemPython(t *testing.T) {
	realAnsible, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Fatalf("ansible-playbook is required on PATH: %v", err)
	}
	probeWith := func(t *testing.T, reply string) wazuhHarnessTools {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(dir+"/python3", []byte("#!/bin/sh\necho '"+reply+"'\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		tools, err := probeWazuhHarnessTools(append(os.Environ(), "PATH="+dir+":"+filepath.Dir(realAnsible)+":"+os.Getenv("PATH")))
		if err != nil {
			t.Fatalf("probe failed: %v", err)
		}
		return tools
	}
	venv := probeWith(t, `{"python":[3,11],"yaml":"6.0","executable":"/work/.venv/bin/python3","venv":true}`)
	err = wazuhSystemPythonError(venv)
	if err == nil || !strings.Contains(err.Error(), "virtual environment") || !strings.Contains(err.Error(), "/work/.venv/bin/python3") {
		t.Fatalf("a venv python passed or the error does not name it: %v", err)
	}
	relative := probeWith(t, `{"python":[3,11],"yaml":"6.0","executable":"python3","venv":false}`)
	if err := wazuhSystemPythonError(relative); err == nil || !strings.Contains(err.Error(), "non-absolute") {
		t.Fatalf("a relative sys.executable passed or is misreported: %v", err)
	}
	system := probeWith(t, `{"python":[3,11],"yaml":"6.0","executable":"/usr/bin/python3","venv":false}`)
	if err := wazuhSystemPythonError(system); err != nil {
		t.Fatalf("a system python was refused: %v", err)
	}
}

// checkWazuhHarnessCI reports whether the Go test job provisions what the
// Wazuh harnesses need before it runs them: a Python at least as new as the
// harness minimum, then PyYAML and the pinned ansible-core, in a step that
// covers the spec shard and comes before `make test-race`.

func checkWazuhHarnessCI(ciYAML string) error {
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string
				If   string `yaml:"if"`
				Uses string
				With map[string]any
				Run  string
			}
		}
	}
	if err := yaml.Unmarshal([]byte(ciYAML), &wf); err != nil {
		return fmt.Errorf("parse CI workflow: %w", err)
	}
	job, ok := wf.Jobs["test"]
	if !ok {
		return fmt.Errorf("CI has no `test` job")
	}
	testStep, pythonOK, installed := -1, false, false
	for i, step := range job.Steps {
		if strings.Contains(step.Run, "make test-race") {
			testStep = i
			break
		}
		if strings.HasPrefix(step.Uses, "actions/setup-python@") {
			version := fmt.Sprint(step.With["python-version"])
			major, minor, found := strings.Cut(version, ".")
			minorNumber, err := strconv.Atoi(strings.SplitN(minor, ".", 2)[0])
			pythonOK = found && major == "3" && err == nil && minorNumber >= wazuhHarnessMinPythonMinor
		}
		coversSpec := step.If == "" || strings.Contains(step.If, "'spec'")
		if coversSpec && strings.Contains(step.Run, "pip install") && strings.Contains(strings.ToLower(step.Run), "pyyaml") &&
			strings.Contains(step.Run, `"ansible-core==`+wazuhHarnessAnsibleCore+`.*"`) {
			installed = true
		}
	}
	switch {
	case testStep < 0:
		return fmt.Errorf("the `test` job has no `make test-race` step")
	case !pythonOK:
		return fmt.Errorf("the `test` job must set up Python 3.%d or newer before running the Wazuh harnesses", wazuhHarnessMinPythonMinor)
	case !installed:
		return fmt.Errorf("the `test` job must install PyYAML and ansible-core==%s.* for the spec shard before `make test-race`", wazuhHarnessAnsibleCore)
	}
	return nil
}

func TestCIProvisionsWazuhHarnessPrerequisites(t *testing.T) {
	raw, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	if err := checkWazuhHarnessCI(string(raw)); err != nil {
		t.Fatal(err)
	}
	const python = "      - uses: actions/setup-python@v5\n        with: {python-version: '3.11'}\n"
	const install = "      - name: deps\n        if: matrix.group == 'spec'\n        run: python3 -m pip install \"ansible-core==2.19.*\" pyyaml\n"
	const test = "      - run: make test-race\n"
	workflow := func(steps string) string { return "jobs:\n  test:\n    steps:\n" + steps }
	for _, tc := range []struct {
		name, steps, want string
	}{
		{"complete", python + install + test, ""},
		{"no PyYAML", python + strings.Replace(install, " pyyaml", "", 1) + test, "PyYAML"},
		{"unpinned core", python + strings.Replace(install, `"ansible-core==2.19.*"`, "ansible-core", 1) + test, "ansible-core"},
		{"installed after the tests", python + test + install, "before `make test-race`"},
		{"only the cmd shard", python + strings.Replace(install, "'spec'", "'cmd'", 1) + test, "spec shard"},
		{"python too old", strings.Replace(python, "3.11", "3.10", 1) + install + test, "Python 3.11"},
		{"no python step", install + test, "Python 3.11"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkWazuhHarnessCI(workflow(tc.steps))
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
}
