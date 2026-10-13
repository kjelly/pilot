package loginprobe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// maxCapturedOutput bounds what the runner keeps from ssh's stdout/stderr
// (verbose output for one login is a few KiB; a misbehaving server could
// otherwise stream forever).
const maxCapturedOutput = 256 * 1024

// Runner spawns the system OpenSSH client for one login attempt. Everything
// policy-related (identity, host-key trust via sss_ssh_knownhostsproxy,
// disabled forwarding/TTY/other auth methods) lives in the pinned
// ssh_config; the argv only selects that file, the target and the user.
type Runner struct {
	SSHBinary      string
	SSHConfig      string
	User           string
	Command        string
	ConnectTimeout time.Duration
	TotalTimeout   time.Duration
	// Env is the full environment for ssh (no inheritance). LC_ALL=C keeps
	// the diagnostics the classifier reads in English.
	Env []string
}

// NewRunner builds a Runner from cfg.
func NewRunner(cfg Config, homeDir string) Runner {
	return Runner{
		SSHBinary:      cfg.SSHBinary,
		SSHConfig:      cfg.SSHConfig,
		User:           cfg.User,
		Command:        cfg.Command,
		ConnectTimeout: cfg.ConnectTimeout,
		TotalTimeout:   cfg.TotalTimeout,
		Env:            []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "LANG=C", "HOME=" + homeDir},
	}
}

// RawResult is what one ssh invocation produced before classification.
type RawResult struct {
	ExitCode int
	TimedOut bool
	Stdout   string
	Stderr   string
	Duration time.Duration
	// StartErr is set when ssh could not be started at all (missing
	// binary, permission): the attempt counts as transport failure.
	StartErr error
}

// Argv is the exact command line for target t. -v is required: the
// classifier needs OpenSSH's debug1 lines to tell an authentication
// refusal from a PAM account denial.
func (r Runner) Argv(t Target) []string {
	return []string{
		r.SSHBinary,
		"-F", r.SSHConfig,
		"-v",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=" + strconv.Itoa(int(r.ConnectTimeout/time.Second)),
		"-p", strconv.Itoa(t.Port),
		"-l", r.User,
		t.Host,
		r.Command,
	}
}

// Run executes one attempt against t, bounded by TotalTimeout. On timeout
// the whole process group is killed so a hung ProxyCommand dies with ssh.
func (r Runner) Run(ctx context.Context, t Target) RawResult {
	argv := r.Argv(t)
	ctx, cancel := context.WithTimeout(ctx, r.TotalTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = r.Env
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	var stdout, stderr limitedBuffer
	stdout.limit, stderr.limit = maxCapturedOutput, maxCapturedOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	start := time.Now()
	err := cmd.Run()
	res := RawResult{Stdout: stdout.String(), Stderr: stderr.String(), Duration: time.Since(start)}
	if ctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		res.ExitCode = -1
		return res
	}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		res.ExitCode = 0
	case errors.As(err, &exitErr):
		res.ExitCode = exitErr.ExitCode()
	default:
		res.ExitCode = -1
		res.StartErr = fmt.Errorf("start %s: %w", argv[0], err)
	}
	return res
}

// limitedBuffer keeps the first limit bytes and drops the rest.
type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}
