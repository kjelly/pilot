package tools

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/anomalyco/pilot/internal/sandbox"
	"sort"
	"strings"
	"time"
)

type RunInSpecTool struct {
	// Env, when non-nil, runs `inspec` inside the sandbox
	// Environment instead of on the local host. Profiles are
	// searched inside the container under /opt/inspec/profiles
	// by default; override via ProfileMount below.
	Env sandbox.Environment
}

func (t *RunInSpecTool) Spec() *Spec {
	return &Spec{
		Name:        "run_inspec",
		Description: "Execute an InSpec compliance scan and return a summary of failed controls. Requires inspec installed on PATH. Use this to check CIS compliance state before and after changes.",
		RiskLevel:   "low",
		Reversible:  true,
		DryRunSafe:  true,
		Parameters:  runInSpecArgs,
	}
}

func (t *RunInSpecTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	var a struct {
		Profile string `json:"profile"`
		Target  string `json:"target"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return nil, fmt.Errorf("run_inspec: invalid args: %w", err)
	}
	if a.Profile == "" {
		a.Profile = "cis-ubuntu"
	}
	if a.Target == "" {
		a.Target = "local://"
	}

	// Use inspec exec with machine-readable output.
	cliArgs := []string{"exec", a.Profile, "-t", a.Target, "--reporter", "json"}

	// Sandbox routing: when Env is set, run inspec inside the container.
	if t.Env != nil {
		// In the container, the target is always local://. Override
		// unless the user explicitly set target=ssh://... in the args.
		if a.Target == "local://" {
			cliArgs = []string{"exec", a.Profile, "-t", "local://", "--reporter", "json"}
		}
		// Install inspec if missing (best-effort, idempotent).
		_ = t.ensureInSpecInSandbox(ctx)
		res, err := t.Env.Exec(ctx,
			append([]string{"inspec"}, cliArgs...),
			sandbox.ExecOptions{Timeout: 5 * time.Minute})
		if err != nil {
			return &Result{Content: fmt.Sprintf("ERROR: inspec (sandbox): %v\nStderr: %s", err, res.Stderr), IsError: true}, nil
		}
		if res.ExitCode != 0 {
			return &Result{Content: fmt.Sprintf("inspec (sandbox) exited %d\nStderr: %s", res.ExitCode, res.Stderr), IsError: true}, nil
		}
		return &Result{Content: summarizeInSpec(res.Stdout)}, nil
	}

	c, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(c, "inspec", cliArgs...)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return &Result{Content: fmt.Sprintf("ERROR starting inspec: %v (is inspec installed?)", err), IsError: true}, nil
	}

	// Read stdout (JSON output)
	var outSB, errSB strings.Builder
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		outSB.Write(scanner.Bytes())
		outSB.WriteByte('\n')
	}
	escan := bufio.NewScanner(stderr)
	for escan.Scan() {
		errSB.WriteString(escan.Text())
		errSB.WriteString("\n")
	}
	err := cmd.Wait()
	jsonOut := outSB.String()
	if err != nil && jsonOut == "" {
		return &Result{Content: fmt.Sprintf("ERROR: inspec failed: %v\nStderr: %s", err, errSB.String()), IsError: true}, nil
	}

	summary := summarizeInSpec(jsonOut)
	if errSB.Len() > 0 {
		summary += "\n--- stderr ---\n" + errSB.String()
	}
	return &Result{Content: summary}, nil
}

// inspecReport is the partial shape of the JSON that `inspec exec
// --reporter json` produces. InSpec emits a top-level array of
// profile results, each containing a Controls map keyed by control
// ID. We only model the fields we need for summarisation; missing
// fields decode as zero values without error.
type inspecReport []inspecProfile

type inspecProfile struct {
	Controls []inspecControl `json:"controls"`
	// Other top-level fields (name, version, sha256, ...) are
	// ignored on purpose.
}

type inspecControl struct {
	ID             string          `json:"id"`
	Title          string          `json:"title"`
	Desc           string          `json:"desc"`
	Impact         float64         `json:"impact"`
	Refs           []inspecRef     `json:"refs"`
	Tags           map[string]any  `json:"tags"`
	CodeString     string          `json:"code_string"`
	SourceLocation *inspecLocation `json:"source_location,omitempty"`
	Results        []inspecResult  `json:"results"`
}

type inspecRef struct {
	Ref string `json:"ref"`
	URI string `json:"uri"`
}

type inspecLocation struct {
	Ref  string `json:"ref"`
	Line int    `json:"line"`
}

type inspecResult struct {
	Status     string `json:"status"`
	CodeResult struct {
		RunTime   float64   `json:"run_time"`
		StartTime time.Time `json:"start_time"`
	} `json:"code_result"`
	Message string  `json:"message"`
	RunTime float64 `json:"run_time"`
}

// summarizeInSpec parses the JSON output of `inspec exec --reporter json`
// and returns a human-readable summary. It is intentionally tolerant:
// if the JSON is malformed or missing fields, it falls back to whatever
// it can extract (or a one-line diagnostic).
func summarizeInSpec(jsonOut string) string {
	if strings.TrimSpace(jsonOut) == "" {
		return "inspec produced no JSON output"
	}

	var report inspecReport
	if err := json.Unmarshal([]byte(jsonOut), &report); err != nil {
		return fmt.Sprintf("inspec JSON parse failed: %v\n(raw output: %.500s)", err, jsonOut)
	}

	var passes, fails, skips int
	type failedEntry struct {
		ID    string
		Title string
	}
	var failed []failedEntry

	for _, prof := range report {
		for _, ctl := range prof.Controls {
			// If results are missing, treat the control as failed
			// (InSpec normally emits at least one result per
			// control).
			if len(ctl.Results) == 0 {
				fails++
				failed = append(failed, failedEntry{ctl.ID, ctl.Title})
				continue
			}
			// A control passes only if ALL its results passed.
			allPass := true
			for _, r := range ctl.Results {
				switch r.Status {
				case "passed":
					passes++
				case "failed":
					fails++
					allPass = false
				case "skipped":
					skips++
				default:
					// Unknown status: be conservative, treat as fail.
					fails++
					allPass = false
				}
			}
			if !allPass {
				failed = append(failed, failedEntry{ctl.ID, ctl.Title})
			}
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "InSpec summary: pass=%d fail=%d skip=%d\n\n", passes, fails, skips)
	if fails > 0 {
		sb.WriteString("Failed controls (truncated to first 30):\n")
		// Stable order for reproducibility.
		sort.Slice(failed, func(i, j int) bool { return failed[i].ID < failed[j].ID })
		limit := 30
		if len(failed) < limit {
			limit = len(failed)
		}
		for i := 0; i < limit; i++ {
			fmt.Fprintf(&sb, "  - %s — %s\n", failed[i].ID, failed[i].Title)
		}
	}
	return sb.String()
}

// ensureInSpecInSandbox installs InSpec inside the container if it's
// not already present. Idempotent: checks `inspec --version` first.
// The install script is the canonical InSpec one from inspec.io.
//
// Loop engineering motivation: every fresh container is a minimal
// image without inspec. Without this helper, `pilot run --sandbox`
// would need a manual `docker exec <id> curl ...` step.
func (t *RunInSpecTool) ensureInSpecInSandbox(ctx context.Context) error {
	if t.Env == nil {
		return nil
	}
	// Probe: inspec --version. If it exits 0, we're done.
	res, err := t.Env.Exec(ctx,
		[]string{"sh", "-c", "command -v inspec && inspec --version"},
		sandbox.ExecOptions{Timeout: 30 * time.Second})
	if err == nil && res.ExitCode == 0 && strings.TrimSpace(res.Stdout) != "" {
		return nil
	}
	// Install via the canonical install script. We pick up the
	// platform family via /etc/os-release to choose the right
	// package manager.
	res, err = t.Env.Exec(ctx,
		[]string{"sh", "-c",
			`set -e
. /etc/os-release 2>/dev/null || true
case "$ID" in
  ubuntu|debian) apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl gnupg2 ca-certificates && curl -fsSL https://packages.chef.io/files/stable/chef-handler/1.2.0/ubuntu/22.04/chef-handler_1.2.0-1_amd64.deb -o /tmp/chef-handler.deb && dpkg -i /tmp/chef-handler.deb && inspec --version ;;
  rocky|rhel|centos|fedora) dnf install -y inspec ;;
  alpine) apk add --no-cache curl bash && curl -fsSL https://omnitruck.chef.io/install.sh | sh -s -- -P inspec ;;
  *) echo "unsupported distro: $ID" >&2; exit 1 ;;
esac`},
		sandbox.ExecOptions{Timeout: 5 * time.Minute})
	if err != nil {
		return fmt.Errorf("install inspec in sandbox: %w (stderr: %s)", err, res.Stderr)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("install inspec in sandbox exited %d (stderr: %s)",
			res.ExitCode, res.Stderr)
	}
	return nil
}
