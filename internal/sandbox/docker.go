package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// DockerEnvironment is an Environment backed by a single Docker
// container. The container is started with `docker run -d --rm`,
// kept alive via `sleep infinity`, and torn down on Stop with
// `docker rm -f`. All tool calls route through `docker exec`.
//
// Design choices:
//   - --rm means a previous run's container is gone (no name
//     conflict), but if Start is called twice we still defensively
//     `docker rm -f` first to handle crashes between runs.
//   - --network host by default — simplest wiring for the
//     "loop engineering" use case. Override via Network field.
//   - No docker compose, no volume mounts, no env passthrough
//     unless the user explicitly opts in. Sandbox is meant to be
//     disposable and isolated from the host's state.
type DockerEnvironment struct {
	// CLI is the docker binary to invoke. Defaults to "docker".
	CLI string

	// Image is the docker image to run (e.g. "ubuntu:22.04",
	// "rockylinux:9"). Required.
	Image string

	// ContainerName is the name assigned to the container. If
	// empty, a name is generated from os.Hostname() + a timestamp
	// to make it discoverable in `docker ps`.
	ContainerName string

	// Network is the docker --network mode. Default: "host".
	Network string

	// Pull is the docker --pull strategy: "always" | "missing" |
	// "never". Default: "missing".
	Pull string

	// PreferCached is a fast-path optimisation: when set, Start
	// first inspects the image locally and switches Pull to "never"
	// if the image is already present. Saves the round-trip to the
	// registry on every "loop engineering" iteration. When the
	// image is absent, falls back to the configured Pull strategy.
	PreferCached bool

	// Keep prevents Stop() from removing the container; the next
	// Start() with the same Image + ContainerName pair will
	// docker-start the existing container instead of docker-run.
	// Loop engineering: keep the same container across `pilot run`
	// invocations so role provisioning only happens once.
	Keep bool

	// ReadOnlyRootfs adds `--read-only` to docker run, and mounts a
	// tmpfs at /tmp so the container still has a writable scratch
	// area. Combined with --sandbox-dry-run this lets users preview
	// a playbook without committing any writes to the image layer.
	ReadOnlyRootfs bool

	// init toggles `docker run --init`. Strongly recommended: docker
	// tini reaps zombies and forwards signals (SIGTERM) to PID 1,
	// which is what makes "ansible service module" correctly
	// stop/start daemons inside the sandbox. Default true.
	init bool

	// Mounts are host:container[:ro] bind mounts to add to docker
	// run. Used so the playbook under test can reference files on
	// the host (e.g. ./site.yml) without copying them in.
	Mounts []SandboxMount

	// changedPaths is populated by Stop() with the list of files the
	// container modified during its lifetime (from `docker diff`).
	// Loop engineering cares a lot about this -- knowing what
	// changed is the entry point for the next iteration.
	changedPaths []string

	// Timeout is the per-exec default. Zero means 5m.
	Timeout time.Duration

	// ReadinessTimeout is the maximum time Start will wait for the
	// container to accept `docker exec`. Zero means 30s.
	ReadinessTimeout time.Duration

	containerID string // set by Start
	cliPath     string // cached from LookPath
}

// SandboxMount is one host->container bind mount. Container
// path must be absolute. RO=true makes the mount read-only.
type SandboxMount struct {
	HostPath      string
	ContainerPath string
	RO            bool
}

// NewDockerEnvironment returns a DockerEnvironment with sensible
// defaults. Image must be set before Start.
func NewDockerEnvironment(image string) *DockerEnvironment {
	return &DockerEnvironment{
		Image:            image,
		Network:          "host",
		Pull:             "missing",
		Timeout:          5 * time.Minute,
		ReadinessTimeout: 30 * time.Second,
		init:             true,
	}
}

// Name returns "docker:<image>" so it shows up clearly in logs and
// proposals.
func (e *DockerEnvironment) Name() string {
	if e.Image == "" {
		return "docker:<unset>"
	}
	return "docker:" + e.Image
}

// IsAvailable checks the docker daemon is reachable and the
// configured image can be inspected (or will be pulled at Start).
func (e *DockerEnvironment) IsAvailable(ctx context.Context) error {
	if err := e.resolveCLI(); err != nil {
		return err
	}
	// `docker info` exits non-zero if the daemon is down.
	res, err := e.dockerCmd(ctx, "info", "--format", "{{.ServerVersion}}")
	if err != nil {
		return fmt.Errorf("docker daemon unreachable: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("docker info failed (exit %d): %s", res.ExitCode, res.Stderr)
	}
	return nil
}

// Start brings the container up. Steps:
//  1. Resolve docker CLI path.
//  2. Defensively `docker rm -f <name>` (idempotent; ignores "not found").
//  3. `docker run -d --rm --network <Network> --pull <Pull> --name
//     <Name> <Image> sleep infinity`.
//  4. Capture the container ID from stdout.
//  5. Wait for readiness: poll `docker exec <id> /bin/true` until
//     exit 0 or readiness timeout.
//
// Returns an error if any step fails. On error, Stop is called
// automatically to clean up partial state.
func (e *DockerEnvironment) Start(ctx context.Context) error {
	if e.Image == "" {
		return errors.New("sandbox.DockerEnvironment: Image is required")
	}
	if err := e.resolveCLI(); err != nil {
		return err
	}
	if e.ContainerName == "" {
		e.ContainerName = defaultContainerName()
	}

	// Keep-mode: if a previously-kept container with this name
	// already exists, just start it. The image, mounts, and init
	// settings of the existing container are unchanged; this is
	// exactly the loop-engineering fast path.
	if e.Keep {
		inspectRes, ierr := e.dockerCmd(ctx, "inspect",
			"--format", "{{.Id}}", e.ContainerName)
		if ierr == nil && inspectRes.ExitCode == 0 {
			id := strings.TrimSpace(inspectRes.Stdout)
			if id != "" {
				startRes, serr := e.dockerCmd(ctx, "start", id)
				if serr != nil {
					return fmt.Errorf("docker start kept container %q: %w",
						e.ContainerName, serr)
				}
				if startRes.ExitCode != 0 {
					return fmt.Errorf("docker start %q failed (exit %d): %s",
						e.ContainerName, startRes.ExitCode, startRes.Stderr)
				}
				e.containerID = id
				return nil
			}
		}
		// No kept container found; fall through to a fresh docker run.
	}

	// Pre-flight: confirm image exists or can be pulled.
	if err := e.ensureImage(ctx); err != nil {
		return err
	}

	// PreferCached fast path: if the image is locally present,
	// switch Pull to "never" so docker run doesn't phone home.
	// Saves ~1-3s per iteration when the image is already cached.
	pull := e.Pull
	if pull == "" {
		pull = "missing"
	}
	if e.PreferCached {
		if res, err := e.dockerCmd(ctx, "image", "inspect", e.Image,
			"--format", "{{.Id}}"); err == nil && res.ExitCode == 0 {
			pull = "never"
		}
	}

	// Defensive cleanup of any stale container with the same name.
	// --rm only kicks in on graceful stop, so a crash may leak.
	if res, err := e.dockerCmd(ctx, "rm", "-f", e.ContainerName); err != nil {
		// "No such container" is fine; anything else is suspicious.
		if res == nil || !strings.Contains(res.Stderr, "No such container") {
			return fmt.Errorf("cleanup stale container %q: %w (stderr: %s)",
				e.ContainerName, err, stderrString(res))
		}
	}

	network := e.Network
	if network == "" {
		network = "host"
	}

	args := []string{
		"run", "-d",
		"--rm",
		"--network", network,
		"--name", e.ContainerName,
		"--pull", pull,
	}
	if e.init {
		// tini as PID 1: forwards signals (SIGTERM) to children so
		// ansible's "service" module can stop/start daemons properly.
		args = append(args, "--init")
	}
	if e.ReadOnlyRootfs {
		// Read-only root + tmpfs scratch space. Lets users preview a
		// playbook without committing any writes to the image layer.
		args = append(args, "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=512m")
	}
	for _, m := range e.Mounts {
		mp := m.HostPath + ":" + m.ContainerPath
		if m.RO {
			mp += ":ro"
		}
		args = append(args, "-v", mp)
	}
	if e.Keep {
		// Omit --rm when keep is on so the container outlives Stop.
		// We strip --rm from the args we just built.
		args = stripArg(args, "--rm")
	}
	args = append(args, e.Image)
	// PID 1 long-running process. tail -f /dev/null works on every
	// minimal image (scratch, distroless) and uses less memory than
	// sleep infinity. tail is part of coreutils on every distro.
	args = append(args, "tail", "-f", "/dev/null")

	res, err := e.dockerCmd(ctx, args...)
	if err != nil {
		return fmt.Errorf("docker run: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("docker run failed (exit %d): %s",
			res.ExitCode, res.Stderr)
	}
	e.containerID = strings.TrimSpace(res.Stdout)
	if e.containerID == "" {
		return errors.New("docker run returned no container ID")
	}

	// Wait for readiness.
	if err := e.waitReady(ctx); err != nil {
		_ = e.Stop(ctx)
		return err
	}
	return nil
}

// stderrString safely returns stderr from an ExecResult pointer,
// returning "" if the pointer is nil.
func stderrString(r *ExecResult) string {
	if r == nil {
		return ""
	}
	return r.Stderr
}

// stripArg removes a single occurrence of an exact argv slot from
// args. Used by Start to omit --rm when Keep is set.
func stripArg(args []string, target string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a != target {
			out = append(out, a)
		}
	}
	return out
}

// Stop tears the container down. Idempotent: safe to call
// multiple times, and safe to call if Start was never called.
//
// Behaviour:
//  1. Capture the set of changed filesystem paths via `docker diff`
//     and store on the receiver.
//  2. Print a short summary to stderr so a human running
//     `pilot run --sandbox` immediately sees what changed.
//  3. If Keep is set, do NOT remove the container. The container
//     stays around for the next `pilot run --sandbox-keep` to
//     re-start. Loop-engineering fast path.
//  4. Otherwise, docker rm -f. "No such container" is fine.
func (e *DockerEnvironment) Stop(ctx context.Context) error {
	if e.containerID == "" && e.ContainerName == "" {
		return nil
	}
	name := e.ContainerName
	if name == "" {
		name = e.containerID
	}

	// 1. Detect changed files before we tear down.
	e.changedPaths = e.detectChangedPaths(ctx, name)

	// 2. Surface to the user.
	if len(e.changedPaths) > 0 {
		fmt.Fprintf(os.Stderr, "sandbox: %d file(s) changed in %s\n",
			len(e.changedPaths), name)
		show := e.changedPaths
		if len(show) > 20 {
			show = show[:20]
		}
		for _, p := range show {
			fmt.Fprintf(os.Stderr, "  %s\n", p)
		}
		if len(e.changedPaths) > 20 {
			fmt.Fprintf(os.Stderr, "  ... (%d more)\n", len(e.changedPaths)-20)
		}
	}

	if e.Keep {
		if e.containerID != "" {
			_, _ = e.dockerCmd(ctx, "stop", e.containerID)
		}
		fmt.Fprintf(os.Stderr, "sandbox: kept container %s for reuse\n", name)
		return nil
	}

	// 3. Tear down.
	res, err := e.dockerCmd(ctx, "rm", "-f", name)
	if err != nil {
		return fmt.Errorf("docker rm: %w", err)
	}
	if res.ExitCode != 0 && !strings.Contains(res.Stderr, "No such container") {
		return fmt.Errorf("docker rm failed (exit %d): %s",
			res.ExitCode, res.Stderr)
	}
	e.containerID = ""
	return nil
}

// ChangedPaths returns the list of files the container modified
// during its lifetime, as captured by Stop(). Nil when Stop has
// not run or the container reported no changes.
func (e *DockerEnvironment) ChangedPaths() []string {
	return e.changedPaths
}

// detectChangedPaths runs `docker diff <name>` and parses the
// A/C/D rows.
//
//	A = added
//	C = changed
//	D = deleted
func (e *DockerEnvironment) detectChangedPaths(ctx context.Context, name string) []string {
	res, err := e.dockerCmd(ctx, "diff", name)
	if err != nil || res.ExitCode != 0 {
		return nil
	}
	var out []string
	for _, line := range strings.Split(res.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if len(line) < 3 {
			continue
		}
		switch line[0] {
		case 'A', 'C', 'D':
			out = append(out, strings.TrimSpace(line[1:]))
		}
	}
	sort.Strings(out)
	return out
}

// ConnectionInfo returns the container ID with `docker` connection
// type. Ansible's `connection: docker` plugin will then talk to the
// container directly via the docker daemon.
func (e *DockerEnvironment) ConnectionInfo() AnsibleConnection {
	return AnsibleConnection{
		Host:           e.containerID,
		ConnectionType: "docker",
		ContainerID:    e.containerID,
		User:           "root", // default; ansible's docker conn allows override
	}
}

// Exec runs argv inside the container via `docker exec`.
//
// Note on the shell: the `docker exec` argv is passed directly to
// `docker exec <id> <argv...>` — no shell on the host side. Inside
// the container the program runs without a shell unless the program
// itself forks one. This matches pilot's "no shell" stance.
func (e *DockerEnvironment) Exec(ctx context.Context, argv []string, opts ExecOptions) (*ExecResult, error) {
	if e.containerID == "" {
		return nil, errors.New("sandbox.DockerEnvironment: not started (containerID empty)")
	}
	if len(argv) == 0 {
		return nil, errors.New("sandbox.DockerEnvironment.Exec: empty argv")
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = e.Timeout
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dockerArgs := []string{"exec"}
	if opts.WorkDir != "" {
		dockerArgs = append(dockerArgs, "-w", opts.WorkDir)
	}
	for _, kv := range opts.Env {
		dockerArgs = append(dockerArgs, "-e", kv)
	}
	dockerArgs = append(dockerArgs, e.containerID)
	dockerArgs = append(dockerArgs, argv...)

	return e.dockerCmd(c, dockerArgs...)
}

// ReadFile reads a file inside the container. Uses `dd if=<path>
// bs=4096` instead of `cat` so the bytes are preserved verbatim —
// no trailing newline stripping, no locale-driven line ending
// translation, no implicit encoding. This matters for files like
// /etc/shadow, /etc/sudoers, and ssh host keys where cat's text-mode
// behaviour would silently corrupt the bytes the caller relies on.
//
// The argv is passed directly to `docker exec`, which delivers it
// verbatim to the container's init — no shell on either side —
// so we don't need shellQuote here. We do reject paths containing
// NUL/newline/CR, since those would either truncate the docker argv
// or cause dd itself to misbehave inside the container.
func (e *DockerEnvironment) ReadFile(ctx context.Context, path string) ([]byte, error) {
	if err := validateExecPath(path); err != nil {
		return nil, err
	}
	res, err := e.Exec(ctx, []string{"dd", "if=" + path, "bs=4096"},
		ExecOptions{Timeout: 30 * time.Second})
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("docker exec dd if=%q failed (exit %d): %s",
			path, res.ExitCode, res.Stderr)
	}
	return []byte(res.Stdout), nil
}

// validateExecPath rejects paths containing bytes that confuse the
// docker argv parser or that would cause dd to misbehave inside the
// container. Empty paths are also rejected. This is a defensive
// sanity check — the upstream tool must have already validated the
// path against its own allow-list.
func validateExecPath(path string) error {
	if path == "" {
		return errors.New("sandbox: empty path")
	}
	for _, r := range path {
		switch r {
		case 0, '\n', '\r':
			return fmt.Errorf("sandbox: invalid byte in path %q", path)
		}
	}
	return nil
}

// WriteFile writes data to a file inside the container. We use a
// one-shot shell pipe because `docker exec` doesn't have a
// `cp-into` primitive. The path is shell-quoted to avoid injection
// from hostile paths. (The path is already validated upstream by
// read_file allow-lists.)
func (e *DockerEnvironment) WriteFile(ctx context.Context, path string, data []byte, mode os.FileMode) error {
	if e.containerID == "" {
		return errors.New("sandbox.DockerEnvironment: not started")
	}
	if strings.ContainsAny(path, "\n\r") {
		return fmt.Errorf("invalid path %q (contains newline)", path)
	}
	modeStr := fmt.Sprintf("%04o", mode.Perm())

	// We stream the file via `docker exec -i ... /bin/sh -c 'cat > path; chmod mode path'`.
	// argv form: docker exec -i <id> /bin/sh -c <cmd>
	shellCmd := fmt.Sprintf("cat > %s && chmod %s %s", shellQuote(path), modeStr, shellQuote(path))
	res, err := e.dockerCmdStdin(ctx, []string{
		"exec", "-i", e.containerID,
		"/bin/sh", "-c", shellCmd,
	}, data, 30*time.Second)
	if err != nil {
		return fmt.Errorf("docker exec write %q: %w", path, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("docker exec write %q failed (exit %d): %s",
			path, res.ExitCode, res.Stderr)
	}
	return nil
}

// ----- internal helpers -----

// resolveCLI looks up the docker binary once and caches the path.
func (e *DockerEnvironment) resolveCLI() error {
	if e.cliPath != "" {
		return nil
	}
	cli := e.CLI
	if cli == "" {
		cli = "docker"
	}
	p, err := exec.LookPath(cli)
	if err != nil {
		return fmt.Errorf("docker CLI %q not found in PATH", cli)
	}
	e.cliPath = p
	return nil
}

// dockerCmd runs a docker command and returns the result.
func (e *DockerEnvironment) dockerCmd(ctx context.Context, args ...string) (*ExecResult, error) {
	return e.dockerCmdStdin(ctx, args, nil, 0)
}

// dockerCmdStdin runs a docker command with optional stdin payload.
func (e *DockerEnvironment) dockerCmdStdin(ctx context.Context, args []string, stdin []byte, timeout time.Duration) (*ExecResult, error) {
	if e.cliPath == "" {
		if err := e.resolveCLI(); err != nil {
			return nil, err
		}
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, e.cliPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	start := time.Now()
	err := cmd.Run()
	dur := time.Since(start)
	res := &ExecResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: dur,
		Cmd:      e.cliPath + " " + strings.Join(args, " "),
	}
	if err != nil {
		// Same timeout handling as LocalEnvironment: a context
		// deadline shows up as an ExitError on Linux.
		if ctx.Err() == context.DeadlineExceeded {
			res.ExitCode = -1
			return res, fmt.Errorf("docker %s: timeout after %s",
				strings.Join(args, " "), timeout)
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			res.ExitCode = exitErr.ExitCode()
			return res, nil
		}
		return res, fmt.Errorf("docker %s: %w", strings.Join(args, " "), err)
	}
	res.ExitCode = 0
	return res, nil
}

// ensureImage checks the image is locally present. We do not pull
// here — the --pull flag on `docker run` handles that. We just
// fail early if --pull=never is set and the image is missing.
func (e *DockerEnvironment) ensureImage(ctx context.Context) error {
	res, err := e.dockerCmd(ctx, "image", "inspect", e.Image, "--format", "{{.Id}}")
	if err != nil {
		return err
	}
	if res.ExitCode == 0 {
		return nil
	}
	if e.Pull == "never" {
		return fmt.Errorf("image %q not present locally and --pull=never", e.Image)
	}
	// Otherwise `docker run --pull <strategy>` will fetch it.
	return nil
}

// waitReady polls `docker exec <id> /bin/true` until exit 0 or
// the readiness timeout elapses.
func (e *DockerEnvironment) waitReady(ctx context.Context) error {
	timeout := e.ReadinessTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)
	backoff := 100 * time.Millisecond
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("container %s not ready after %s",
				e.containerID, timeout)
		}
		res, err := e.dockerCmd(ctx, "exec", e.containerID, "/bin/true")
		if err == nil && res.ExitCode == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		// Cap backoff at 2s.
		if backoff < 2*time.Second {
			backoff *= 2
		}
	}
}

// defaultContainerName generates a name like
// "pilot-sandbox-<host>-<unix>-<6hex>". The 6-hex suffix is a
// crypto/rand read so two `pilot run`s issued in the same second
// from the same host (e.g. a parallel CI matrix) do not collide
// on a still-running container from a previous run.
func defaultContainerName() string {
	host, _ := os.Hostname()
	if host == "" {
		host = "pilot"
	}
	host = strings.ToLower(host)
	clean := func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '-':
			return r
		}
		return -1
	}
	host = strings.Map(clean, host)
	if host == "" {
		host = "pilot"
	}
	return fmt.Sprintf("pilot-sandbox-%s-%d-%s",
		host, time.Now().Unix(), NewNanoID())
}

// NewNanoID returns a 6-character lowercase hex string. crypto/rand
// for collision resistance in CI; falls back to time-based entropy
// if /dev/urandom is unavailable (should never happen on Linux).
// Exported because the multi-host sandbox builder needs it for
// per-host container names.
func NewNanoID() string {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%06x", time.Now().UnixNano()&0xffffff)
	}
	return fmt.Sprintf("%06x", uint32(b[0])<<16|uint32(b[1])<<8|uint32(b[2]))
}

// shellQuote wraps s in single quotes, escaping any embedded single
// quotes (the standard POSIX shell-quoting trick). The result is
// safe to embed inside a `/bin/sh -c` argument.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// CreateSnapshot commits the current container's filesystem to a temporary image name
// and returns the image tag as the snapshot ID.
func (e *DockerEnvironment) CreateSnapshot(ctx context.Context) (string, error) {
	if e.containerID == "" {
		return "", fmt.Errorf("container not running; cannot snapshot")
	}
	snapshotTag := fmt.Sprintf("pilot-snapshot-%s-%d", e.ContainerName, time.Now().UnixNano())
	res, err := e.dockerCmd(ctx, "commit", e.containerID, snapshotTag)
	if err != nil {
		return "", fmt.Errorf("docker commit failed: %w", err)
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("docker commit failed (exit %d): %s", res.ExitCode, res.Stderr)
	}
	return snapshotTag, nil
}

// RestoreSnapshot stops/destroys the current container and starts a new one from the snapshot image.
func (e *DockerEnvironment) RestoreSnapshot(ctx context.Context, snapshotID string) error {
	if snapshotID == "" {
		return fmt.Errorf("empty snapshot ID")
	}

	// 1. Stop the current running container.
	_ = e.Stop(ctx)

	// 2. Set the image to the snapshot image tag.
	e.Image = snapshotID

	// 3. Start a new container from this image.
	if err := e.Start(ctx); err != nil {
		return fmt.Errorf("failed to start container from snapshot image %q: %w", snapshotID, err)
	}

	return nil
}

// DeleteSnapshot deletes the temporary committed image.
func (e *DockerEnvironment) DeleteSnapshot(ctx context.Context, snapshotID string) error {
	if snapshotID == "" {
		return nil
	}
	_, err := e.dockerCmd(ctx, "rmi", snapshotID)
	return err
}

// Compile-time check: DockerEnvironment satisfies Environment.
// Keep this in production source so accidental interface drift
// (e.g. adding a method to Environment) fails the build immediately,
// not just the tests.
var _ Environment = (*DockerEnvironment)(nil)
