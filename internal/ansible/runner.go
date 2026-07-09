package ansible

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// Result captures the outcome of running an Ansible command
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
	Cmd      string
}

// Runner wraps ansible-playbook invocation
type Runner struct {
	Binary       string        // path to ansible-playbook (default "ansible-playbook")
	Defaults     []string      // extra args always passed, e.g. ["-i", "inv.yml"]
	Timeout      time.Duration // per-run timeout
	StdoutWriter io.Writer     // if set, stdout is streamed in real-time here
	StderrWriter io.Writer     // if set, stderr is streamed in real-time here
	Stdin        io.Reader     // if set, connects to ansible-playbook's stdin (needed for --ask-vault-pass / --ask-become-pass)
}

func NewRunner(defaults ...string) *Runner {
	return &Runner{
		Binary:   "ansible-playbook",
		Defaults: defaults,
		Timeout:  30 * time.Minute,
	}
}

// Run executes ansible-playbook with the given extra args.
// Captures stdout/stderr separately and returns exit code.
func (r *Runner) Run(ctx context.Context, args ...string) (*Result, error) {
	allArgs := append([]string{}, r.Defaults...)
	allArgs = append(allArgs, args...)

	c, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()

	cmd := exec.CommandContext(c, r.Binary, allArgs...)
	if r.Stdin != nil {
		cmd.Stdin = r.Stdin
	}
	var stdout, stderr bytes.Buffer
	if r.StdoutWriter != nil {
		cmd.Stdout = io.MultiWriter(&stdout, r.StdoutWriter)
	} else {
		cmd.Stdout = &stdout
	}
	if r.StderrWriter != nil {
		cmd.Stderr = io.MultiWriter(&stderr, r.StderrWriter)
	} else {
		cmd.Stderr = &stderr
	}

	start := time.Now()
	err := cmd.Run()
	dur := time.Since(start)

	res := &Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: dur,
		Cmd:      r.Binary + " " + strings.Join(allArgs, " "),
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		res.ExitCode = exitErr.ExitCode()
	} else if err != nil {
		return res, fmt.Errorf("ansible run failed: %w", err)
	} else {
		res.ExitCode = 0
	}
	return res, nil
}

// Check runs ansible-playbook --check --diff and returns the result
func (r *Runner) Check(ctx context.Context, args ...string) (*Result, error) {
	checkArgs := append([]string{"--check", "--diff"}, args...)
	return r.Run(ctx, checkArgs...)
}

// Available checks if ansible-playbook is on PATH
func (r *Runner) Available() bool {
	_, err := exec.LookPath(r.Binary)
	return err == nil
}

// Version returns the ansible-playbook --version output
func (r *Runner) Version(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, r.Binary, "--version")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// SyntaxCheck runs `ansible-playbook --syntax-check` on the given
// playbook. It is a cheap pre-flight that catches obvious YAML / Jinja
// errors before the agent loop burns LLM tokens on a doomed run.
//
// If inventory is empty, the playbook's own hosts clause is used (or
// "all" if none is set). Limit is optional.
func (r *Runner) SyntaxCheck(ctx context.Context, playbook, inventory, limit string) (*Result, error) {
	args := []string{playbook, "--syntax-check"}
	if inventory != "" {
		args = append(args, "-i", inventory)
	}
	if limit != "" {
		args = append(args, "--limit", limit)
	}
	return r.Run(ctx, args...)
}

// RunWithTimeout is a one-shot invocation that overrides the Runner's
// default timeout for this call only. Useful when a single playbook
// needs more (or less) wall-clock than the Runner default of 30m.
//
// Falls back to Runner.Timeout if timeout <= 0.
func (r *Runner) RunWithTimeout(ctx context.Context, timeout time.Duration, args ...string) (*Result, error) {
	saved := r.Timeout
	if timeout > 0 {
		r.Timeout = timeout
	}
	defer func() { r.Timeout = saved }()
	return r.Run(ctx, args...)
}

// PlaybookArgs is a typed bag of every ansible-playbook option that
// pilot exposes through the run_ansible / apply_patch tools and the
// pilot run CLI. The zero value is valid and produces the bare
// `ansible-playbook <playbook>` command.
//
// All pointer / slice fields are skipped when zero / nil — a missing
// field in JSONL decodes to "not set" and the corresponding flag is
// not added to the argv. This keeps the wire format additive
// (forward-compatible with new flags).
type PlaybookArgs struct {
	Playbook string

	// Host targeting
	Inventory string
	Limit     string

	// Tag / var selection
	Tags          []string
	SkipTags      []string
	ExtraVarsFile string // path to a JSON file written by the caller; -e @<file>
	RawExtraVars  string // raw `-e k=v k2=v2` value

	// Privilege / connection
	Become     *bool
	Forks      *int
	User       string
	Connection string

	// Security / cache
	VaultPasswordFile string
	Diff              *bool

	// Execution control
	Timeout    *int
	FlushCache *bool
}

// BuildArgs converts a PlaybookArgs into the argv passed to
// `ansible-playbook`. Flags appear in a stable, deterministic order
// so audit logs are reproducible.
func BuildArgs(p PlaybookArgs) []string {
	args := []string{p.Playbook}

	// Host targeting
	if p.Inventory != "" {
		args = append(args, "-i", p.Inventory)
	}
	if p.Limit != "" {
		args = append(args, "--limit", p.Limit)
	}

	// Tag / var selection
	if len(p.Tags) > 0 {
		args = append(args, "--tags", strings.Join(p.Tags, ","))
	}
	if len(p.SkipTags) > 0 {
		args = append(args, "--skip-tags", strings.Join(p.SkipTags, ","))
	}
	if p.ExtraVarsFile != "" {
		args = append(args, "-e", "@"+p.ExtraVarsFile)
	} else if p.RawExtraVars != "" {
		args = append(args, "-e", p.RawExtraVars)
	}

	// Privilege / connection
	if p.Become != nil {
		if *p.Become {
			args = append(args, "--become")
		} else {
			args = append(args, "--become=false")
		}
	}
	if p.Forks != nil && *p.Forks > 0 {
		args = append(args, "--forks", fmt.Sprintf("%d", *p.Forks))
	}
	if p.User != "" {
		args = append(args, "--user", p.User)
	}
	if p.Connection != "" {
		args = append(args, "--connection", p.Connection)
	}

	// Security / cache
	if p.VaultPasswordFile != "" {
		args = append(args, "--vault-password-file", p.VaultPasswordFile)
	}
	if p.Diff != nil && *p.Diff {
		args = append(args, "--diff")
	}

	// Execution control
	if p.FlushCache != nil && *p.FlushCache {
		args = append(args, "--flush-cache")
	}
	// (Timeout is applied via Runner.RunWithTimeout, not as an argv flag.)

	return args
}

// FilterOutput parses the raw Ansible stdout and filters out the redundant
// "ok" and "skipping" lines to save context window tokens, keeping task headers,
// changed, failed, and play recap lines.
func FilterOutput(stdout string) string {
	lines := strings.Split(stdout, "\n")
	var filtered []string
	var inPlayRecap bool
	var currentTaskHeader string
	var taskLines []string
	hasChangesOrErrors := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "PLAY RECAP **************************") {
			inPlayRecap = true
			if currentTaskHeader != "" && (hasChangesOrErrors || len(taskLines) > 0) {
				filtered = append(filtered, currentTaskHeader)
				filtered = append(filtered, taskLines...)
				currentTaskHeader = ""
			}
			filtered = append(filtered, line)
			continue
		}
		if inPlayRecap {
			filtered = append(filtered, line)
			continue
		}
		if strings.HasPrefix(trimmed, "TASK [") || strings.HasPrefix(trimmed, "PLAY [") {
			if currentTaskHeader != "" && (hasChangesOrErrors || len(taskLines) > 0) {
				filtered = append(filtered, currentTaskHeader)
				filtered = append(filtered, taskLines...)
			}
			currentTaskHeader = line
			taskLines = nil
			hasChangesOrErrors = false
			continue
		}

		if strings.Contains(trimmed, "failed:") || strings.Contains(trimmed, "fatal:") || strings.Contains(trimmed, "changed:") || strings.Contains(trimmed, "FAILED!") {
			hasChangesOrErrors = true
			taskLines = append(taskLines, line)
		} else if strings.Contains(trimmed, "ok:") || strings.Contains(trimmed, "skipping:") {
			continue
		} else {
			if currentTaskHeader != "" {
				taskLines = append(taskLines, line)
			} else {
				filtered = append(filtered, line)
			}
		}
	}
	if currentTaskHeader != "" && (hasChangesOrErrors || len(taskLines) > 0) {
		filtered = append(filtered, currentTaskHeader)
		filtered = append(filtered, taskLines...)
	}

	return strings.Join(filtered, "\n")
}
