package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/images"
	"github.com/anomalyco/pilot/internal/dockertarget"
)

// dockerTargetCmd is the parent for `pilot docker-target ...`.
//
// Subcommands:
//
//	up       bring up a docker container to use as a target host
//	down     tear down a target (docker rm -f + remove state)
//	list     list all known targets with live status
//	run      run an ansible playbook against the target (uses generated inventory)
//	verify   run a spec against the target (`pilot verify <spec>` semantics)
//	exec     run a single command inside the container (`docker exec <name> ...`)
//
// docker-target is the user-facing entry to internal/dockertarget.
// It does NOT spin up a sandbox for the agent — it just gives you a
// "host = docker container" to point ansible at. Compare with
// `pilot sandbox`, which controls the *agent tool execution env*.
var dockerTargetCmd = &cobra.Command{
	Use:   "docker-target",
	Short: "Manage Docker containers used as Ansible target hosts",
	Long: `docker-target treats a Docker container as a disposable VM.

Use cases:
  - Smoke-test a playbook without touching your real infra
  - Iterate on a spec's expected behavior in a clean OS image
  - Apply role-by-role (DNS / NTP / Keycloak) on a throwaway host

Typical flow:
  pilot docker-target up    --image ubuntu:24.04 --name infra-test
  pilot docker-target run   --name infra-test playbooks/apply/<x>.yml -e ...
  pilot docker-target verify --name infra-test docs/verification/<x>.md
  pilot docker-target exec   --name infra-test -- ss -tulnH
  pilot docker-target down  --name infra-test

State lives under cfg.DataDir/docker-targets.json. The container is
brought up with --network host --privileged by default so apt and
systemd work; override via --network / --no-privileged.
`,
}

func init() {
	rootCmd.AddCommand(dockerTargetCmd)
	dockerTargetCmd.AddCommand(dtUpCmd)
	dockerTargetCmd.AddCommand(dtDownCmd)
	dockerTargetCmd.AddCommand(dtListCmd)
	dockerTargetCmd.AddCommand(dtRunCmd)
	dockerTargetCmd.AddCommand(dtVerifyCmd)
	dockerTargetCmd.AddCommand(dtExecCmd)
	dockerTargetCmd.AddCommand(dtShowInventoryCmd)
	dockerTargetCmd.AddCommand(dtSnapshotCmd)
	dockerTargetCmd.AddCommand(dtRollbackCmd)
}

// ---- shared flags ---------------------------------------------------------

var (
	dtName         string
	dtImage        string
	dtImagePilot   string
	dtHostname     string
	dtNetwork      string
	dtNoPrivileged bool
	dtSystemd      bool
	dtExtraArgs    []string
	dtHosts        []string
)

// resolveDataDir returns the active pilot data dir. Centralised so the
// `docker-target` subcommands pick up the same --data-dir flag that
// every other command does.
func resolveDataDir() string {
	if dataDir != "" {
		return dataDir
	}
	// Fall back to the same logic as loadConfig: config default.
	// We don't want to call loadConfig here (it also hits Ollama
	// discovery indirectly via cfg). Replicate the default.
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "pilot")
}

// dtNewManager builds a Manager against the resolved data dir.
func dtNewManager() (*dockertarget.Manager, error) {
	return dockertarget.NewManager(resolveDataDir())
}

// ---- up -------------------------------------------------------------------

var dtUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Bring up a new docker target",
	Long: `Bring up a docker container as a disposable Ansible target host.

Examples:
  pilot docker-target up --image ubuntu:24.04 --name infra-test
  pilot docker-target up --image-pilot ubuntu-24.04 --name infra-test
  pilot docker-target up --image rockylinux:9 --name rocky-1 \
      --hostname rocky-1 --network bridge --no-privileged

The --image-pilot shortcut resolves to pilot-target:<arg>, e.g.
--image-pilot ubuntu-24.04 -> pilot-target:ubuntu-24.04. Build the
image first with ./images/build.sh.
`,
	RunE: runDtUp,
}

func init() {
	dtUpCmd.Flags().StringVar(&dtName, "name", "", "container name (also ansible host key)")
	dtUpCmd.Flags().StringVar(&dtImage, "image", "", "docker image (e.g. ubuntu:24.04, rockylinux:9)")
	dtUpCmd.Flags().StringVar(&dtImagePilot, "image-pilot", "", "shortcut for --image pilot-target:<arg> (e.g. ubuntu-24.04). Mutually exclusive with --image.")
	dtUpCmd.Flags().StringVar(&dtHostname, "hostname", "", "container --hostname (default = --name)")
	dtUpCmd.Flags().StringVar(&dtNetwork, "network", "host", "docker --network (host|bridge|none)")
	dtUpCmd.Flags().BoolVar(&dtNoPrivileged, "no-privileged", false, "disable docker --privileged (default: enabled)")
	dtUpCmd.Flags().BoolVar(&dtSystemd, "systemd", false, "boot systemd as PID 1 so `systemctl`/`service` tasks and systemd-resolved work (requires an image that ships systemd, e.g. --image-pilot ubuntu-24.04; implies privileged)")
	dtUpCmd.Flags().StringSliceVar(&dtExtraArgs, "docker-arg", nil, "extra arg for `docker run` (may repeat)")
	dtUpCmd.Flags().StringSliceVar(&dtHosts, "hosts", nil, "additional ansible host aliases for this target (may repeat). All aliases route to the same container.")
}

func runDtUp(cmd *cobra.Command, args []string) error {
	if dtName == "" {
		return fmt.Errorf("--name is required")
	}
	if dtImage == "" && dtImagePilot == "" {
		return fmt.Errorf("--image or --image-pilot is required")
	}
	if dtImage != "" && dtImagePilot != "" {
		return fmt.Errorf("--image and --image-pilot are mutually exclusive")
	}
	if dtImage == "" {
		dtImage = "pilot-target:" + dtImagePilot
	}
	m, err := dtNewManager()
	if err != nil {
		return err
	}
	// Auto-build the pre-baked pilot-target image if it's missing
	// locally, so users don't need a separate `./images/build.sh` step.
	// Only applies to `pilot-target:*` tags (whether reached via
	// --image-pilot or an explicit --image pilot-target:...); plain
	// user images are left to docker run to pull/resolve.
	if variant, ok := strings.CutPrefix(dtImage, "pilot-target:"); ok {
		if err := ensurePilotImage(context.Background(), m, variant, dtSystemd, cmd.ErrOrStderr()); err != nil {
			return err
		}
	}
	opts := dockertarget.Options{
		Name:      dtName,
		Image:     dtImage,
		Network:   dtNetwork,
		Hostname:  dtHostname,
		Hosts:     dtHosts,
		ExtraArgs: dtExtraArgs,
	}
	if !dtNoPrivileged {
		t := true
		opts.Privileged = &t
	} else {
		f := false
		opts.Privileged = &f
	}
	if dtSystemd {
		s := true
		opts.Systemd = &s
	}
	tgt, err := m.Up(context.Background(), opts)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "✓ target %s up\n", tgt.Name)
	fmt.Fprintf(out, "  container_id : %s\n", shortCID(tgt.ContainerID))
	fmt.Fprintf(out, "  image        : %s\n", tgt.Image)
	fmt.Fprintf(out, "  hostname     : %s\n", tgt.Hostname)
	fmt.Fprintf(out, "  network      : %s\n", tgt.Network)
	fmt.Fprintf(out, "  privileged   : %v\n", tgt.Privileged)
	fmt.Fprintf(out, "  systemd      : %v\n", tgt.Systemd)
	fmt.Fprintf(out, "  inventory    : `pilot docker-target show-inventory --name %s`\n", tgt.Name)
	return nil
}

// ---- down -----------------------------------------------------------------

var dtDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Tear down a docker target (docker rm -f + clear state)",
	RunE:  runDtDown,
}

func init() {
	dtDownCmd.Flags().StringVar(&dtName, "name", "", "target name to tear down")
}

func runDtDown(cmd *cobra.Command, args []string) error {
	if dtName == "" {
		return fmt.Errorf("--name is required")
	}
	m, err := dtNewManager()
	if err != nil {
		return err
	}
	if err := m.Down(context.Background(), dtName); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ target %s down\n", dtName)
	return nil
}

// ---- list -----------------------------------------------------------------

var dtListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all docker targets with live status",
	RunE:  runDtList,
}

func init() {
	dtListCmd.Flags().BoolP("json", "j", false, "output as JSON (for scripts)")
}

func runDtList(cmd *cobra.Command, args []string) error {
	m, err := dtNewManager()
	if err != nil {
		return err
	}
	all, err := m.List(context.Background())
	if err != nil {
		return err
	}
	if cmd.Flags().Changed("json") {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(all)
	}
	if len(all) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "(no targets — `pilot docker-target up` to start one)")
		return nil
	}
	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tIMAGE\tSTATUS\tCONTAINER_ID\tCREATED")
	for _, t := range all {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			t.Name, t.Image, t.Status, shortID(t.ContainerID), t.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	return tw.Flush()
}

// ---- show-inventory -------------------------------------------------------

var dtShowInventoryCmd = &cobra.Command{
	Use:   "show-inventory",
	Short: "Print the generated inventory for a target (YAML)",
	RunE:  runDtShowInventory,
}

func init() {
	dtShowInventoryCmd.Flags().StringVar(&dtName, "name", "", "target name")
}

func runDtShowInventory(cmd *cobra.Command, args []string) error {
	if dtName == "" {
		return fmt.Errorf("--name is required")
	}
	if !validDockerTag(dtSnapshotTag) {
		return fmt.Errorf("--tag %q must match [a-zA-Z0-9_./-]+ (no '+' or whitespace)", dtSnapshotTag)
	}
	m, err := dtNewManager()
	if err != nil {
		return err
	}
	t, err := m.Get(context.Background(), dtName)
	if err != nil {
		return err
	}
	inv, err := t.RenderInventory()
	if err != nil {
		return err
	}
	_, err = io.WriteString(cmd.OutOrStdout(), inv)
	return err
}

// ---- run ------------------------------------------------------------------

var dtRunCmd = &cobra.Command{
	Use:   "run <playbook.yml> [<extra>...]",
	Short: "Run an ansible playbook against the docker target",
	Long: `Passes --inventory and --limit automatically based on the target name.

Everything after the playbook is forwarded verbatim to ansible-playbook.

Examples:
  pilot docker-target run --name infra-test \
      playbooks/apply/core-infra-provider-apply.yml -e infra_role=dns
  pilot docker-target run --name infra-test \
      playbooks/apply/core-infra-provider-apply.yml \
      -e infra_role=dns --check --diff
`,
	Args: cobra.MinimumNArgs(1),
	RunE: runDtRun,
}

func init() {
	dtRunCmd.Flags().StringVar(&dtName, "name", "", "target name")
	dtRunCmd.Flags().String("check", "", "passed to ansible-playbook: --check (true) or omitted (false)")
}

func runDtRun(cmd *cobra.Command, args []string) error {
	if dtName == "" {
		return fmt.Errorf("--name is required")
	}
	if !validDockerTag(dtSnapshotTag) {
		return fmt.Errorf("--tag %q must match [a-zA-Z0-9_./-]+ (no '+' or whitespace)", dtSnapshotTag)
	}
	m, err := dtNewManager()
	if err != nil {
		return err
	}
	t, err := m.Get(context.Background(), dtName)
	if err != nil {
		return err
	}
	if t.Status != dockertarget.StatusRunning {
		return fmt.Errorf("target %q is not running (status=%s); bring it back up first", dtName, t.Status)
	}

	// Stage the generated inventory to a temp file so ansible-playbook
	// can -i it. The user could also pass --inventory themselves but
	// then they'd need to know the generated form — we make the common
	// case one flag.
	inv, err := t.RenderInventory()
	if err != nil {
		return err
	}
	invPath, cleanup, err := writeTempInventory(inv)
	if err != nil {
		return err
	}
	defer cleanup()

	playbook := args[0]
	extra := args[1:]
	ansibleArgs := []string{playbook, "-i", invPath}
	// Only auto-inject -l when the user hasn't specified target_group
	// (which is the playbook's hosts: pattern). The user is in charge
	// of choosing which one to drive.
	if !extraHasTargetGroup(extra) {
		ansibleArgs = append(ansibleArgs, "-l", t.Hostname)
	}
	ansibleArgs = append(ansibleArgs, extra...)
	if cmd.Flags().Changed("check") {
		v, _ := cmd.Flags().GetString("check")
		if strings.EqualFold(v, "true") || v == "1" {
			ansibleArgs = append(ansibleArgs, "--check", "--diff")
		}
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "▶ ansible-playbook %s\n", strings.Join(ansibleArgs, " "))
	return execAnsiblePlaybook(cmd.OutOrStdout(), ansibleArgs...)
}

// ---- verify ---------------------------------------------------------------

var dtVerifyCmd = &cobra.Command{
	Use:   "verify <spec.md> [<extra>...]",
	Short: "Run `pilot verify` against the docker target",
	Long: `Convenience wrapper: forwards to ` + "`pilot verify`" + ` with the
generated inventory and --limit set automatically.

Examples:
  pilot docker-target verify --name infra-test \\
      docs/verification/core-infra-provider.md
`,
	Args: cobra.MinimumNArgs(1),
	RunE: runDtVerify,
}

func init() {
	dtVerifyCmd.Flags().StringVar(&dtName, "name", "", "target name")
}

func runDtVerify(cmd *cobra.Command, args []string) error {
	if dtName == "" {
		return fmt.Errorf("--name is required")
	}
	m, err := dtNewManager()
	if err != nil {
		return err
	}
	t, err := m.Get(context.Background(), dtName)
	if err != nil {
		return err
	}
	if t.Status != dockertarget.StatusRunning {
		return fmt.Errorf("target %q is not running (status=%s)", dtName, t.Status)
	}

	// Stage inventory (same dance as run)
	inv, err := t.RenderInventory()
	if err != nil {
		return err
	}
	invPath, cleanup, err := writeTempInventory(inv)
	if err != nil {
		return err
	}
	defer cleanup()

	spec := args[0]
	extra := args[1:]
	pilotArgs := []string{"verify", spec, "-i", invPath, "-l", t.Hostname}
	pilotArgs = append(pilotArgs, extra...)
	fmt.Fprintf(cmd.ErrOrStderr(), "▶ pilot %s\n", strings.Join(pilotArgs, " "))
	return execPilot(cmd.OutOrStdout(), pilotArgs...)
}

// ---- exec -----------------------------------------------------------------

var dtExecCmd = &cobra.Command{
	Use:   "exec -- <argv...>",
	Short: "Run a single command inside the docker target (no host shell)",
	Long: `Forwards argv directly to ` + "`docker exec`" + `. No shell is
involved on the host. To use shell features, invoke ` + "`sh -c`" + `
yourself.

Examples:
  pilot docker-target exec --name infra-test -- ss -tulnH
  pilot docker-target exec --name infra-test -- sh -c 'uname -a && cat /etc/os-release'
`,
	Args: cobra.MinimumNArgs(1),
	RunE: runDtExec,
}

func init() {
	dtExecCmd.Flags().StringVar(&dtName, "name", "", "target name")
}

func runDtExec(cmd *cobra.Command, args []string) error {
	if dtName == "" {
		return fmt.Errorf("--name is required")
	}
	m, err := dtNewManager()
	if err != nil {
		return err
	}
	res, err := m.Exec(context.Background(), dtName, args)
	if err != nil {
		return err
	}
	if res.Stdout != "" {
		cmd.OutOrStdout().Write([]byte(res.Stdout))
	}
	if res.Stderr != "" {
		cmd.ErrOrStderr().Write([]byte(res.Stderr))
	}
	// Do NOT fail on non-zero exit. Many legitimate exec calls
	// (grep -q, test -f, apt list checks) intentionally exit non-zero.
	// The user is in charge of interpreting the output. We do not
	// want to push them to wrap every exec in .
	return nil
}

// ---- helpers --------------------------------------------------------------

// shortCID returns the 12-char docker container ID prefix to match
// `docker ps --format "{{.ID}}"` so users can paste the value into
// other docker commands without confusion. Distinct from helpers.shortID
// (which truncates to 8 chars for run/proposal IDs).
func shortCID(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

// dockerBin returns the docker binary to invoke, honouring the
// PILOT_DOCKER_BIN override (the same one internal/dockertarget uses)
// so tests / power users can point at a shim.
func dockerBin() string {
	if b := os.Getenv("PILOT_DOCKER_BIN"); b != "" {
		return b
	}
	return "docker"
}

// ensurePilotImage builds the pre-baked pilot-target image on demand
// when it is missing locally, so `pilot docker-target up --image-pilot
// <variant>` just works without a separate `./images/build.sh` step.
//
// The Dockerfile is embedded in the binary (package images), so this
// works regardless of CWD. The build context is an empty temp dir —
// the pilot-target Dockerfiles have no COPY/ADD, so nothing else is
// needed. Build output is streamed so a multi-minute apt install does
// not look hung; there is no timeout (matches ansible-playbook — the
// user can Ctrl-C).
func ensurePilotImage(ctx context.Context, m *dockertarget.Manager, variant string, needInit bool, progress io.Writer) error {
	tag := "pilot-target:" + variant
	// Already present? `docker image inspect` exits 0 iff the tag exists.
	present := false
	if res, err := m.DockerRaw(ctx, "image", "inspect", tag); err == nil && res.ExitCode == 0 {
		present = true
	}
	// When --systemd is requested the image must be able to boot
	// /sbin/init. Images built before --systemd support lack it, so a
	// stale local tag would otherwise fail at `docker run` with a
	// cryptic OCI "stat /sbin/init: no such file" error. Probe for it
	// and rebuild instead.
	if present && needInit && !imageHasInit(ctx, m, tag) {
		fmt.Fprintf(progress, "▶ image %s has no /sbin/init (predates --systemd support); rebuilding…\n", tag)
		present = false
	}
	if present {
		return nil
	}
	df, ok := images.DockerfileFor(variant)
	if !ok {
		return fmt.Errorf("image %s not found locally and no built-in Dockerfile for variant %q (known: %s); build/tag it yourself or pass --image",
			tag, variant, strings.Join(images.Variants(), ", "))
	}
	tmpDir, err := os.MkdirTemp("", "pilot-img-build-*")
	if err != nil {
		return fmt.Errorf("create build context: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	if err := os.WriteFile(filepath.Join(tmpDir, "Dockerfile"), df, 0o644); err != nil {
		return fmt.Errorf("stage Dockerfile: %w", err)
	}
	fmt.Fprintf(progress, "▶ image %s not found locally; building from built-in Dockerfile (one-time, takes a few minutes)…\n", tag)
	c := newCmd(ctx, dockerBin(), "build", "-t", tag, "-f", filepath.Join(tmpDir, "Dockerfile"), tmpDir)
	c.Stdout = progress
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("build %s: %w", tag, err)
	}
	fmt.Fprintf(progress, "✓ built %s\n", tag)
	return nil
}

// imageHasInit reports whether the image can boot systemd as PID 1, i.e.
// whether /sbin/init exists inside it. Runs a throwaway `test -e` with
// the entrypoint overridden so the image's own CMD/init is not invoked.
func imageHasInit(ctx context.Context, m *dockertarget.Manager, tag string) bool {
	res, err := m.DockerRaw(ctx, "run", "--rm", "--entrypoint", "test", tag, "-e", "/sbin/init")
	return err == nil && res.ExitCode == 0
}

// execAnsiblePlaybook invokes the locally-installed ansible-playbook
// binary. Kept as a thin wrapper so tests / future Windows ports
// have a single seam to patch.
func execAnsiblePlaybook(stdout io.Writer, args ...string) error {
	return execExternal(stdout, "ansible-playbook", args...)
}

// execPilot re-invokes the same pilot binary we're running in. Used
// by `pilot docker-target verify` so the user doesn't have to
// duplicate the verify plumbing.
func execPilot(stdout io.Writer, args ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate pilot binary: %w", err)
	}
	return execExternal(stdout, exe, args...)
}

// execExternal runs a binary with stdout/stderr wired to the caller's
// writers. Honors $PILOT_BIN override so tests can intercept.
func execExternal(stdout io.Writer, bin string, args ...string) error {
	if envBin := os.Getenv("PILOT_BIN_OVERRIDE"); envBin != "" && (bin == "ansible-playbook" || filepath.Base(bin) == filepath.Base(os.Args[0])) {
		// Only honor for the in-process re-invocation. ansible-playbook
		// always comes from PATH.
		_ = envBin
	}
	ctx := context.Background()
	c := newCmd(ctx, bin, args...)
	c.Stdout = stdout
	c.Stderr = os.Stderr
	return c.Run()
}

// newCmd is package-local so tests can swap it for a fake. Default
// implementation is exec.CommandContext with no timeout (the binary
// itself enforces one, and the user can Ctrl-C).
var newCmd = func(ctx context.Context, bin string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, bin, args...)
}

// ---- snapshot -------------------------------------------------------------

var (
	dtSnapshotName string
	dtSnapshotTag  string
)

var dtSnapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Commit the target container as a reusable image tag",
	Long: `Capture the target's current filesystem as a new docker image tag,
so future ` + "`pilot docker-target up --image <tag>`" + ` starts from this
snapshot instead of the original base.

Mirrors ` + "`pilot sandbox snapshot`" + ` for the docker-target feature.

Examples:
  pilot docker-target snapshot --name infra-test --tag my-baseline
  # later, restore by tag:
  pilot docker-target rollback --name infra-test --image my-baseline
`,
	RunE: runDtSnapshot,
}

func init() {
	dtSnapshotCmd.Flags().StringVar(&dtName, "name", "", "target name (required)")
	dtSnapshotCmd.Flags().StringVar(&dtSnapshotTag, "tag", "", "image tag to write (required)")
	_ = dtSnapshotCmd.MarkFlagRequired("tag")
}

func runDtSnapshot(cmd *cobra.Command, args []string) error {
	if dtName == "" {
		return fmt.Errorf("--name is required")
	}
	if !validDockerTag(dtSnapshotTag) {
		return fmt.Errorf("--tag %q must match [a-zA-Z0-9_./-]+ (no '+' or whitespace)", dtSnapshotTag)
	}
	m, err := dtNewManager()
	if err != nil {
		return err
	}
	t, err := m.Get(context.Background(), dtName)
	if err != nil {
		return err
	}
	if t.Status != dockertarget.StatusRunning {
		return fmt.Errorf("target %q is not running (status=%s); cannot snapshot", dtName, t.Status)
	}
	res, err := m.DockerRaw(context.Background(), "commit", dtName, dtSnapshotTag)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("docker commit: %s", res.Stderr)
	}
	imageID := strings.TrimSpace(res.Stdout)
	fmt.Fprintf(cmd.OutOrStdout(), "✓ snapshotted %s as %s (image id: %s)\n", dtName, dtSnapshotTag, shortCID(imageID))
	return nil
}

// ---- rollback -------------------------------------------------------------

var (
	dtRollbackImage string
)

var dtRollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Recreate a target from a previously snapshotted image tag",
	Long: `Stops the existing target (if running), then brings it back up from
the given image tag. The state record is preserved (Name / ContainerID
are reset to the new container).

Mirrors ` + "`pilot sandbox rollback`" + ` for the docker-target feature.

Examples:
  pilot docker-target rollback --name infra-test --image my-baseline
`,
	RunE: runDtRollback,
}

func init() {
	dtRollbackCmd.Flags().StringVar(&dtName, "name", "", "target name (required)")
	dtRollbackCmd.Flags().StringVar(&dtRollbackImage, "image", "", "image tag to roll back to (required)")
	_ = dtRollbackCmd.MarkFlagRequired("image")
}

func runDtRollback(cmd *cobra.Command, args []string) error {
	if dtName == "" {
		return fmt.Errorf("--name is required")
	}
	if dtRollbackImage == "" {
		return fmt.Errorf("--image is required")
	}
	if !validDockerTag(dtRollbackImage) {
		return fmt.Errorf("--image %q must match [a-zA-Z0-9_./:.-]+ (must be a valid docker image reference)", dtRollbackImage)
	}
	m, err := dtNewManager()
	if err != nil {
		return err
	}
	// Capture the current target so we can preserve Hostname / Hosts /
	// Network / Privileged after rollback.
	t, err := m.Get(context.Background(), dtName)
	if err != nil {
		return err
	}
	// 1. Tear down (idempotent if container already gone)
	if err := m.Down(context.Background(), dtName); err != nil {
		return err
	}
	// 2. Bring back up from the snapshot image, preserving the rest
	//    of the target config.
	upOpts := dockertarget.Options{
		Name:      t.Name,
		Image:     dtRollbackImage,
		Network:   t.Network,
		Hostname:  t.Hostname,
		Hosts:     t.Hosts,
		ExtraArgs: nil,
	}
	if t.Privileged {
		tt := true
		upOpts.Privileged = &tt
	} else {
		ff := false
		upOpts.Privileged = &ff
	}
	if t.Systemd {
		ss := true
		upOpts.Systemd = &ss
	}
	newT, err := m.Up(context.Background(), upOpts)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ rolled back %s to image %s (new container: %s)\n",
		dtName, dtRollbackImage, shortCID(newT.ContainerID))
	return nil
}

// extraHasTargetGroup scans the user's extra-args for an explicit
// -e target_group= or -e 'target_group=...' so we don't both inject
// -l <name> and let the user run against a different group.
func extraHasTargetGroup(extra []string) bool {
	for _, e := range extra {
		if e == "-e" || e == "--extra-vars" {
			continue
		}
		// -e target_group=dns
		if strings.HasPrefix(e, "target_group=") || strings.HasPrefix(e, "target_group:") {
			return true
		}
		// -e target_group=dns (joined form)
		if strings.HasPrefix(e, "-e target_group=") || strings.HasPrefix(e, "-etarget_group=") {
			return true
		}
		// --extra-vars target_group=dns (joined form)
		if strings.HasPrefix(e, "--extra-vars target_group=") {
			return true
		}
	}
	return false
}

// validDockerTag returns true for a string safe to pass as a docker
// image tag. Rejects '+', spaces, and other shell-significant
// characters that lead to "invalid reference format" from docker
// commit / docker run.
func validDockerTag(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == '-' || r == '/' || r == ':':
		default:
			return false
		}
	}
	return true
}
