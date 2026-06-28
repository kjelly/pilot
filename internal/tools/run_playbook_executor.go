package tools

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/anomalyco/pilot/internal/ansible"
	"github.com/anomalyco/pilot/internal/sandbox"
)

// playbookExecutor abstracts "how do I invoke ansible-playbook for
// this call". Three strategies exist today:
//
//   - localExecutor:      runs ansible-playbook on the host.
//   - dockerConnExecutor: host runs ansible-playbook with a generated
//                         `connection: docker` inventory pointing at
//                         the sandbox container. Requires host-side
//                         docker-py + community.docker.
//   - dockerExecExecutor: copies the playbook + inventory + extra-vars
//                         into the sandbox container and runs
//                         ansible-playbook there via `docker exec`.
//                         No host Python deps needed.
//
// Each strategy receives a fully-validated request (paths checked,
// extra_vars temp file created, check/timeout decided) and returns
// the captured ansible.Result plus any infrastructure error.
//
// This replaced the previous "if/else if/else if" ladder in
// RunPlaybookTool.Execute. New strategies (podman-exec, ssh, etc.)
// just satisfy this interface.
type playbookExecutor interface {
	Name() string
	Run(ctx context.Context, req playbookExecRequest) (*ansible.Result, error)
}

// playbookExecRequest is the bag of facts every executor needs.
// All path/validation work has already been done by the caller.
type playbookExecRequest struct {
	PlaybookPath  string
	InventoryPath string
	ExtraVarsFile string
	Check         bool
	Limit         string        // ansible --limit (for inventory generation)
	Timeout       time.Duration // 0 = no override
	EffectiveArgs []string      // ansible.BuildArgs output, host paths
	// GeneratedInventory is true when InventoryPath points at a
	// temp file that prepareRequest created (the rewritten
	// `connection: docker` sandbox inventory). Execute uses this
	// flag to know it must os.Remove the file on the cleanup
	// defer — paths that came from the model or from a flag on
	// the CLI must NEVER be unlinked, only the ones we wrote.
	GeneratedInventory bool
}

// selectExecutor picks the right playbookExecutor for the current
// tool state. Returns an error with an actionable message when the
// configuration is invalid (e.g. docker-exec mode without a docker
// connection).
func (t *RunPlaybookTool) selectExecutor(mode sandbox.SandboxMode) (playbookExecutor, error) {
	// No sandbox: always local. Use the tool's Runner so custom
	// Defaults / Timeout settings are honoured (was H2 bug).
	if t.Env == nil {
		return localExecutor{runner: t.runner()}, nil
	}

	// Sandbox active: any mode requires a docker connection.
	conn, err := t.dockerConnOrError(mode)
	if err != nil {
		return nil, err
	}

	switch mode {
	case sandbox.SandboxModeDockerExec:
		if conn.ContainerID == "" {
			return nil, errors.New(
				"--sandbox-mode=docker-exec: empty container id from Environment")
		}
		return &dockerExecExecutor{containerID: conn.ContainerID}, nil

	case sandbox.SandboxModeDocker:
		return &dockerConnExecutor{env: t.Env, runner: t.runner()}, nil

	default:
		// SandboxModeUnset with a non-nil Env falls back to the
		// docker-connection path (legacy: "" meant docker).
		return &dockerConnExecutor{env: t.Env, runner: t.runner()}, nil
	}
}

// dockerConnOrError centralises the "Env must point at a docker
// container" precondition shared by every sandbox executor (L2).
// Returns the Environment's ConnectionInfo so callers can pull the
// ContainerID for the docker-exec case.
func (t *RunPlaybookTool) dockerConnOrError(_ sandbox.SandboxMode) (sandbox.AnsibleConnection, error) {
	conn := t.Env.ConnectionInfo()
	if conn.ConnectionType != "docker" {
		return conn, fmt.Errorf(
			"sandbox requires a docker ConnectionInfo, got %q", conn.ConnectionType)
	}
	if conn.ContainerID == "" {
		return conn, fmt.Errorf("sandbox ConnectionInfo has empty container id")
	}
	return conn, nil
}

// runner returns the effective ansible.Runner for this tool, falling
// back to a default instance if the caller didn't set one. Used by
// every executor so the tool's Runner settings (Defaults, Timeout)
// are honoured uniformly.
func (t *RunPlaybookTool) runner() *ansible.Runner {
	if t.Runner != nil {
		return t.Runner
	}
	return ansible.NewRunner()
}

// ----- localExecutor -----

type localExecutor struct {
	runner *ansible.Runner
}

func (e localExecutor) Name() string { return "local" }

func (e localExecutor) Run(ctx context.Context, req playbookExecRequest) (*ansible.Result, error) {
	args := req.EffectiveArgs
	if req.Check {
		args = append([]string{"--check", "--diff"}, args...)
	}
	if req.Timeout > 0 {
		return e.runner.RunWithTimeout(ctx, req.Timeout, args...)
	}
	if req.Check {
		return e.runner.Check(ctx, args...)
	}
	return e.runner.Run(ctx, args...)
}

// ----- dockerConnExecutor -----
//
// Runs ansible-playbook on the HOST, but targets the sandbox container
// via a generated `connection: docker` inventory. Requires the host to
// have docker-py + community.docker installed. Honours the tool's
// custom Runner (fixes H2).

type dockerConnExecutor struct {
	env    sandbox.Environment
	runner *ansible.Runner
}

func (e *dockerConnExecutor) Name() string {
	if e.env == nil {
		return "docker-conn"
	}
	return "docker-conn:" + e.env.Name()
}

func (e *dockerConnExecutor) Run(ctx context.Context, req playbookExecRequest) (*ansible.Result, error) {
	// ConnectionInfo and inventory rewriting already happened in
	// the tool's caller (RunPlaybookTool.Execute). Here we just
	// invoke ansible-playbook with the rewritten inventory.
	args := req.EffectiveArgs
	if req.Check {
		args = append([]string{"--check", "--diff"}, args...)
	}
	if req.Timeout > 0 {
		return e.runner.RunWithTimeout(ctx, req.Timeout, args...)
	}
	if req.Check {
		return e.runner.Check(ctx, args...)
	}
	return e.runner.Run(ctx, args...)
}

// ----- dockerExecExecutor -----
//
// Copies the playbook + inventory + extra-vars into the sandbox
// container and runs ansible-playbook THERE via `docker exec`. No
// host-side docker-py needed.

type dockerExecExecutor struct {
	containerID string
}

func (e *dockerExecExecutor) Name() string {
	// Truncate containerID to first 12 chars (the standard short
	// docker id); use built-in min (Go 1.21+).
	id := e.containerID
	if len(id) > 12 {
		id = id[:12]
	}
	return "docker-exec:" + id
}

func (e *dockerExecExecutor) Run(ctx context.Context, req playbookExecRequest) (*ansible.Result, error) {
	args := req.EffectiveArgs
	if req.Check {
		args = append([]string{"--check", "--diff"}, args...)
	}
	der := newDockerExecRunner(e.containerID)
	return der.runInContainer(ctx, req.PlaybookPath, req.InventoryPath, req.ExtraVarsFile, args, req.Timeout)
}
