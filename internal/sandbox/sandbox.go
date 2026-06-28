// Package sandbox abstracts the execution environment that pilot's
// tools target. The default (LocalEnvironment) is a no-op — every
// exec/read/write goes straight to the host where pilot runs.
// DockerEnvironment replaces the local host with a managed container
// so playbooks can be tested in isolation, e.g. for "loop engineering"
// on a host that may not be the actual target.
//
// Two interfaces split the lifecycle/metadata concerns from the
// per-host routing concerns so callers can't accidentally call
// Exec/Read/Write on a multi-host environment without first
// resolving which host they meant:
//
//   - Environment:    single-host; all exec/read/write targets
//                     the same machine.
//   - MultiEnvironment: multi-host; per-host operations go via
//                       Host(name).X(...). The Env-level methods
//                       only exist for inventory/banner plumbing
//                       (Start/Stop/IsAvailable/ConnectionInfo/
//                       Name/Topology).
//
// Adding new backends (SSH, podman, remote docker daemon) only
// requires satisfying the appropriate interface for that backend's
// topology shape.
package sandbox

import (
	"context"
	"os"
	"time"
)

// Environment is the single-host abstraction: every Exec/ReadFile/
// WriteFile targets the same machine. All known single-host
// implementations (LocalEnvironment, DockerEnvironment) satisfy it.
//
// Lifecycle: New → Start → (Exec/ReadFile/WriteFile)* → Stop. Stop is
// idempotent and safe to call even if Start was never called or
// failed partway.
type Environment interface {
	// Start brings the environment up. For LocalEnvironment, this is
	// a no-op. For DockerEnvironment, runs `docker run -d --rm ...`
	// and waits for readiness.
	Start(ctx context.Context) error

	// Stop tears the environment down. Idempotent.
	Stop(ctx context.Context) error

	// Exec runs argv inside the environment. The first element of
	// argv is the program name; the rest are positional arguments.
	// NO shell is involved — implementations call exec.Command(bin,
	// args...) either directly (Local) or via `docker exec` (Docker).
	//
	// Returns combined output and exit code. Implementations should
	// honour opts.Timeout (cancelling the child after the duration).
	Exec(ctx context.Context, argv []string, opts ExecOptions) (*ExecResult, error)

	// ReadFile reads path from the environment. For Local,
	// delegates to os.ReadFile. For Docker, runs
	// `docker exec <id> cat <path>` (via `dd if=<path>`).
	ReadFile(ctx context.Context, path string) ([]byte, error)

	// WriteFile writes data to path inside the environment with
	// the given mode. For Local, delegates to os.WriteFile +
	// Chmod. For Docker, runs `docker exec <id> /bin/sh -c "cat >
	// <path>"` then chmods.
	WriteFile(ctx context.Context, path string, data []byte, mode os.FileMode) error

	// ConnectionInfo returns the ansible inventory fragment that
	// targets this environment. For DockerEnvironment, this is
	// `ConnectionType: "docker"` plus the container ID. For
	// LocalEnvironment, this is `ConnectionType: "local"` with the
	// loopback address.
	ConnectionInfo() AnsibleConnection

	// IsAvailable returns nil if the environment can be brought up
	// right now (docker daemon reachable, image pullable, etc.).
	// Returns an error with an actionable hint otherwise.
	IsAvailable(ctx context.Context) error

	// Name is a short human label for logs and proposals
	// (e.g. "local", "docker:ubuntu:22.04").
	Name() string
}

// MultiEnvironment is the multi-host abstraction. Per-host exec/read/
// write must go via Host(name).X(...) — the Env-level X methods
// return an error to force callers to think about routing.
//
// Implementations:
//   - MultiEnvironment: composes one Environment per HostSpec.
type MultiEnvironment interface {
	// Start brings every host up. If any one fails, the
	// already-started ones are stopped before returning so we never
	// leak containers.
	Start(ctx context.Context) error

	// Stop tears every host down. Idempotent.
	Stop(ctx context.Context) error

	// Host returns the Environment for a named host. Empty string
	// or unknown name returns nil.
	Host(name string) Environment

	// Hosts returns the underlying hosts map (read-only access).
	Hosts() map[string]Environment

	// Topology returns the topology this environment was built from.
	Topology() Topology

	// ConnectionInfo returns a representative ansible connection
	// fragment. Single-host semantics: collapses all hosts to the
	// first one's ConnectionInfo. Use Host(name).ConnectionInfo()
	// for per-host routing.
	ConnectionInfo() AnsibleConnection

	// IsAvailable checks every host's environment in turn.
	IsAvailable(ctx context.Context) error

	// Name is a short human label for logs and proposals
	// (e.g. "docker:multi(3 hosts: web01,db01,cache01)").
	Name() string
}

// Snapshotable is implemented by environments that support state
// snapshot and rollback. Currently only DockerEnvironment.
type Snapshotable interface {
	CreateSnapshot(ctx context.Context) (string, error)
	RestoreSnapshot(ctx context.Context, snapshotID string) error
	DeleteSnapshot(ctx context.Context, snapshotID string) error
}

// ExecOptions tunes an individual Exec call. Zero values are valid:
// Timeout=0 means "no extra limit" (caller's ctx governs).
type ExecOptions struct {
	Timeout time.Duration
	WorkDir string
	Env     []string // KEY=VALUE entries
}

// ExecResult is the outcome of an Exec call. The shape matches
// internal/ansible.Result for cross-package compatibility.
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
	Cmd      string // human-readable form, for logging
}

// AnsibleConnection is the data needed to generate a dynamic
// inventory fragment that points ansible at this environment.
type AnsibleConnection struct {
	// Host is the value for `ansible_host:`. For Docker, this is
	// the container ID (the docker connection plugin looks it up
	// via the docker daemon). For local, "127.0.0.1".
	Host string

	// Port is the SSH port when ConnectionType="ssh". Zero
	// otherwise.
	Port int

	// User is the SSH/login user. Empty means "current user" for
	// local, "root" for docker.
	User string

	// ConnectionType is one of "local", "docker", "ssh". The
	// matching `ansible_connection:` value.
	ConnectionType string

	// ContainerID is the raw docker container ID, when applicable.
	// It is also stored in Host above; this field is for tools that
	// want the ID without a string round-trip.
	ContainerID string
}

// Compile-time check: multiEnv satisfies MultiEnvironment but MUST
// NOT satisfy Environment. If someone re-adds Exec/Read/Write to
// multiEnv the second line stops compiling — which is the whole
// point of the interface split (see C2 in the design notes).
var (
	_ MultiEnvironment = (*multiEnv)(nil)
	_ Environment      = (*LocalEnvironment)(nil)
	_ Environment      = (*DockerEnvironment)(nil)
)
