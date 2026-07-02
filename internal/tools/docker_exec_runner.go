package tools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/anomalyco/pilot/internal/ansible"
)

// dockerExecRunner executes an ansible-playbook invocation INSIDE a
// running Docker container via `docker cp` + `docker exec`. It is the
// sandbox-mode="docker-exec" path that does not require host-side
// docker-py or community.docker.
//
// The flow:
//  1. `docker cp` the playbook, inventory, and extra-vars file into
//     /tmp inside the container (each under a unique pilot- prefixed
//     name so parallel pilot runs can't collide).
//  2. `docker exec` ansible-playbook inside the container with the
//     three paths rewritten to the container's /tmp.
//  3. Stream stdout/stderr back into an *ansible.Result so the rest
//     of pilot (audit, formatter, banner) treats it identically to
//     a host-side runner.
//
// Cleanup uses `docker exec rm` so we never leak tmpfiles even if
// the process is killed mid-run.
type dockerExecRunner struct {
	containerID string
	// DockerBinary is the docker CLI to invoke. Empty means
	// fall back to "docker" (looked up in $PATH).
	DockerBinary string
	// StagingDir is the directory inside the container where
	// files are copied. Empty means "/tmp".
	StagingDir   string
	stdoutWriter io.Writer
	stderrWriter io.Writer
}

func newDockerExecRunner(containerID string) *dockerExecRunner {
	return &dockerExecRunner{containerID: containerID}
}

func (r *dockerExecRunner) docker() string {
	if r.DockerBinary != "" {
		return r.DockerBinary
	}
	return "docker"
}

func (r *dockerExecRunner) staging() string {
	if r.StagingDir != "" {
		return r.StagingDir
	}
	return "/tmp"
}

// runInContainer executes `ansible-playbook` with the given args
// inside the container. The args MUST be the output of
// ansible.BuildArgs (so host paths have already been validated).
// We rewrite three of the args to container paths:
//   - the playbook positional arg (first non-flag arg)
//   - the inventory (-i)
//   - the extra-vars file (-e @<file>)
//
// before copying the source files into the container with `docker cp`.
//
// Returns an *ansible.Result with the same shape as Runner.Run so
// the caller's downstream code (banner, audit, formatter) is
// unchanged.
func (r *dockerExecRunner) runInContainer(
	ctx context.Context,
	playbookPath string,
	inventoryPath string,
	extraVarsFile string,
	ansibleArgs []string, // output of ansible.BuildArgs — already flag-formatted
	timeout time.Duration,
) (*ansible.Result, error) {
	res := &ansible.Result{}
	start := time.Now()

	// Three files may need translation:
	//   - playbookPath (always required)
	//   - inventoryPath (optional — may be "")
	//   - extraVarsFile (optional — may be "")
	// We stage each one and rewrite the matching argv slot.
	type staged struct {
		hostPath string
		cntPath  string
		// WhichBuildArg index inside ansibleArgs that points at
		// this path. -1 means "the playbook is the positional
		// arg at index 0".
		argIdx int
	}
	var stages []staged

	// Stage 1: playbook (positional arg, always ansibleArgs[0])
	if playbookPath == "" {
		return res, errors.New("dockerExecRunner: empty playbook path")
	}
	pbName := fmt.Sprintf("pilot-pb-%d.yml", time.Now().UnixNano())
	pbCnt := filepath.ToSlash(filepath.Join(r.staging(), pbName))
	if err := r.cpInto(ctx, playbookPath, pbCnt); err != nil {
		return res, fmt.Errorf("docker cp playbook: %w", err)
	}
	stages = append(stages, staged{playbookPath, pbCnt, 0})

	// Stage 2: inventory (-i flag)
	if inventoryPath != "" {
		idx, ok := findFlagValue(ansibleArgs, "-i")
		if !ok {
			return res, fmt.Errorf("inventory path %q but no -i in args", inventoryPath)
		}
		invName := fmt.Sprintf("pilot-inv-%d.yml", time.Now().UnixNano())
		invCnt := filepath.ToSlash(filepath.Join(r.staging(), invName))
		if err := r.cpInto(ctx, inventoryPath, invCnt); err != nil {
			return res, fmt.Errorf("docker cp inventory: %w", err)
		}
		stages = append(stages, staged{inventoryPath, invCnt, idx})
	}

	// Stage 3: extra-vars file (-e @<file>)
	if extraVarsFile != "" {
		idx, ok := findExtraVarsFile(ansibleArgs)
		if !ok {
			return res, fmt.Errorf("extra-vars file %q but no -e @<file> in args", extraVarsFile)
		}
		evName := fmt.Sprintf("pilot-vars-%d.json", time.Now().UnixNano())
		evCnt := filepath.ToSlash(filepath.Join(r.staging(), evName))
		if err := r.cpInto(ctx, extraVarsFile, evCnt); err != nil {
			return res, fmt.Errorf("docker cp extra-vars: %w", err)
		}
		stages = append(stages, staged{extraVarsFile, evCnt, idx})
	}

	// Build container-side argv by rewriting staged indices.
	cntArgs := append([]string(nil), ansibleArgs...)
	for _, s := range stages {
		cntArgs[s.argIdx] = s.cntPath
	}

	// Best-effort cleanup of staged files. Don't fail the run if
	// cleanup fails — the playbook result is the source of truth.
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, s := range stages {
			_ = r.execRm(cleanCtx, s.cntPath)
		}
	}()

	// Build the docker exec command:
	//   docker exec [-t] <container> ansible-playbook <cntArgs...>
	dockerArgs := []string{"exec"}
	// -t so the container's ansible-playbook can use TTY output
	// formatting (e.g. --diff colors). No-op when no TTY is
	// attached to pilot itself; harmless either way.
	dockerArgs = append(dockerArgs, "-t", r.containerID, "ansible-playbook")
	dockerArgs = append(dockerArgs, cntArgs...)

	res.Cmd = r.docker() + " " + strings.Join(dockerArgs, " ")

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, r.docker(), dockerArgs...)
	// Connect stdout/stderr directly so the user sees ansible
	// progress in real time and so the captured output for the
	// result is the same stream the user sees.
	var stdout, stderr strings.Builder
	if r.stdoutWriter != nil {
		cmd.Stdout = io.MultiWriter(&stdout, r.stdoutWriter)
	} else {
		cmd.Stdout = &stdout
	}
	if r.stderrWriter != nil {
		cmd.Stderr = io.MultiWriter(&stderr, r.stderrWriter)
	} else {
		cmd.Stderr = &stderr
	}

	err := cmd.Run()
	res.Duration = time.Since(start)
	res.Stdout = stdout.String()
	res.Stderr = stderr.String()

	if ctx.Err() == context.DeadlineExceeded {
		res.ExitCode = -1
		return res, fmt.Errorf("dockerExecRunner: timeout after %s", timeout)
	}
	if err != nil {
		// *exec.ExitError means the process exited non-zero; we
		// still want to surface the captured output, not just
		// the error.
		if exitErr, ok := err.(*exec.ExitError); ok {
			res.ExitCode = exitErr.ExitCode()
			return res, nil
		}
		res.ExitCode = -1
		return res, fmt.Errorf("dockerExecRunner: %w", err)
	}
	res.ExitCode = 0
	return res, nil
}

// cpInto copies a host file into the container at the given
// container path. The destination is given as an absolute
// container path; `docker cp` creates the basename if the parent
// directory already exists (which /tmp does).
func (r *dockerExecRunner) cpInto(ctx context.Context, hostPath, cntPath string) error {
	if r.containerID == "" {
		return errors.New("cpInto: empty container id")
	}
	// docker cp SRC CONTAINER:DEST
	cmd := exec.CommandContext(ctx, r.docker(), "cp", hostPath, r.containerID+":"+cntPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker cp %s -> %s:%s: %w (%s)", hostPath, r.containerID, cntPath, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// execRm removes a file inside the container via `docker exec rm`.
// Best-effort: errors are returned to the caller for logging.
func (r *dockerExecRunner) execRm(ctx context.Context, cntPath string) error {
	cmd := exec.CommandContext(ctx, r.docker(), "exec", r.containerID, "rm", "-f", cntPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker exec rm %s: %w (%s)", cntPath, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// findFlagValue returns the index inside args that holds the
// value of `flag` (the index right after the flag itself).
// Returns false if `flag` is not present.
func findFlagValue(args []string, flag string) (int, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return i + 1, true
		}
	}
	return -1, false
}

// findExtraVarsFile looks for `-e @<path>` in args and returns
// the index of the path (right after the -e flag).
func findExtraVarsFile(args []string) (int, bool) {
	for i, a := range args {
		if a == "-e" && i+1 < len(args) {
			val := args[i+1]
			if strings.HasPrefix(val, "@") {
				return i + 1, true
			}
		}
	}
	return -1, false
}
