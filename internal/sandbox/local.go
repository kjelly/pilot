package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// LocalEnvironment is the default Environment: every call goes
// straight to the host OS where pilot runs. Start/Stop are no-ops
// and ConnectionInfo reports ansible_connection=local.
//
// This is the implementation that matches pilot's pre-sandbox
// behaviour. Tools that route through Environment see no change
// when LocalEnvironment is the active backend.
type LocalEnvironment struct{}

// NewLocalEnvironment returns a ready-to-use LocalEnvironment.
func NewLocalEnvironment() *LocalEnvironment { return &LocalEnvironment{} }

// Start is a no-op.
func (e *LocalEnvironment) Start(_ context.Context) error { return nil }

// Stop is a no-op.
func (e *LocalEnvironment) Stop(_ context.Context) error { return nil }

// Name returns "local".
func (e *LocalEnvironment) Name() string { return "local" }

// IsAvailable always returns nil (the host is always available).
func (e *LocalEnvironment) IsAvailable(_ context.Context) error { return nil }

// ConnectionInfo reports the loopback address with local connection.
func (e *LocalEnvironment) ConnectionInfo() AnsibleConnection {
	return AnsibleConnection{
		Host:           "127.0.0.1",
		ConnectionType: "local",
		// User left empty → ansible uses the running user.
	}
}

// Exec runs argv on the local host via exec.CommandContext. The
// argv is passed as-is (no shell), matching the long-standing
// pilot behaviour. Implements the same capture/timeout semantics
// as internal/tools/run_command.go.
func (e *LocalEnvironment) Exec(ctx context.Context, argv []string, opts ExecOptions) (*ExecResult, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("sandbox: empty argv")
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(c, argv[0], argv[1:]...)
	if opts.WorkDir != "" {
		cmd.Dir = opts.WorkDir
	}
	if len(opts.Env) > 0 {
		cmd.Env = append(os.Environ(), opts.Env...)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	dur := time.Since(start)

	res := &ExecResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: dur,
		Cmd:      strings.Join(argv, " "),
	}
	if err != nil {
		// Context cancellation due to opts.Timeout presents as an
		// *exec.ExitError (process killed by signal) on Linux, but
		// in some Go versions it can also surface as a plain error
		// or even nil error if the process happened to exit cleanly
		// just as the deadline fired. Use duration as the reliable
		// signal: if we ran for at least the configured timeout
		// (minus a small grace period to absorb scheduler jitter),
		// the deadline fired.
		//
		// The 100ms grace handles the rare case where a process
		// exited cleanly microseconds before its deadline — the
		// err might be a real "exit 0" but the caller's intent
		// (don't wait longer than N) was still met.
		timeoutFloor := timeout - 100*time.Millisecond
		if timeoutFloor < 0 {
			timeoutFloor = 0
		}
		if ctx.Err() == context.DeadlineExceeded || dur >= timeoutFloor {
			res.ExitCode = -1
			return res, fmt.Errorf("sandbox.LocalEnvironment.Exec: timeout after %s", timeout)
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			res.ExitCode = exitErr.ExitCode()
			return res, nil
		}
		return res, fmt.Errorf("sandbox.LocalEnvironment.Exec: %w", err)
	}
	res.ExitCode = 0
	return res, nil
}

// ReadFile reads a local file. The path is returned as-is from the
// caller; tools must enforce their own allow-lists upstream.
func (e *LocalEnvironment) ReadFile(_ context.Context, path string) ([]byte, error) {
	return os.ReadFile(path)
}

// WriteFile writes a local file with the given mode.
func (e *LocalEnvironment) WriteFile(_ context.Context, path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// Compile-time check: LocalEnvironment satisfies Environment.
// Keep this in production source so accidental interface drift
// (e.g. adding a method to Environment) fails the build immediately,
// not just the tests.
var _ Environment = (*LocalEnvironment)(nil)
