package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// sandboxCmd is the parent for all `pilot sandbox ...` subcommands.
// These do not require an LLM or Ollama; they manage Docker
// containers used as loop-engineering scratchpads.
//
// Subcommands:
//
//	list       - show all kept / running pilot sandbox containers
//	prune      - delete all pilot sandbox containers
//	attach     - docker exec -it <name> bash (interactive)
//	snapshot   - commit current container state as a new image tag
//	rollback   - revert to a previously snapshotted image
//	warmup     - pre-pull a docker image so the next --sandbox is fast
//	status     - show the running container's uptime, image, etc.
var sandboxCmd = &cobra.Command{
	Use:   "sandbox",
	Short: "Manage Docker containers used as sandboxed test environments",
	Long: `Loop-engineering helpers for the sandbox mode.

The default flow is: 'pilot run --sandbox' starts a fresh container
and tears it down at the end. 'pilot sandbox' gives you finer
control: pre-pull images, snapshot a known-good state, attach an
interactive shell, or wipe all leftover containers in one go.

All subcommands operate on containers whose name starts with
"pilot-sandbox-". They are safe to run while a ` + "`pilot run`" + `
session is in progress (they target a different process).`,
}

func init() {
	rootCmd.AddCommand(sandboxCmd)
	sandboxCmd.AddCommand(sandboxListCmd)
	sandboxCmd.AddCommand(sandboxPruneCmd)
	sandboxCmd.AddCommand(sandboxAttachCmd)
	sandboxCmd.AddCommand(sandboxSnapshotCmd)
	sandboxCmd.AddCommand(sandboxRollbackCmd)
	sandboxCmd.AddCommand(sandboxWarmupCmd)
	sandboxCmd.AddCommand(sandboxStatusCmd)
}

// sandboxListItem is one row of the `pilot sandbox list` output.
type sandboxListItem struct {
	Name     string    `json:"name"`
	Image    string    `json:"image"`
	State    string    `json:"state"`
	Status   string    `json:"status"`
	Created  time.Time `json:"created"`
	Keepable bool      `json:"keepable"`
}

var sandboxListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all pilot sandbox containers (running and stopped)",
	RunE:  runSandboxList,
}

func runSandboxList(cmd *cobra.Command, args []string) error {
	res, err := dockerCmd(context.Background(),
		"ps", "-a", "--filter", "name=pilot-sandbox-",
		"--format", "{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t{{.CreatedAt}}")
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("docker ps: %s", res.Stderr)
	}
	var items []sandboxListItem
	for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 5)
		if len(parts) < 5 {
			continue
		}
		created, _ := time.Parse("2006-01-02 15:04:05 -0700 MST", parts[4])
		items = append(items, sandboxListItem{
			Name:     parts[0],
			Image:    parts[1],
			State:    parts[2],
			Status:   parts[3],
			Created:  created,
			Keepable: strings.Contains(parts[3], "keepable"),
		})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Created.After(items[j].Created)
	})
	out, _ := json.MarshalIndent(items, "", "  ")
	fmt.Println(string(out))
	return nil
}

var sandboxPruneCmd = &cobra.Command{
	Use:   "prune",
	Short: "Delete all pilot sandbox containers (running and stopped)",
	RunE:  runSandboxPrune,
}

func runSandboxPrune(cmd *cobra.Command, args []string) error {
	res, err := dockerCmd(context.Background(),
		"ps", "-a", "-q", "--filter", "name=pilot-sandbox-")
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("docker ps: %s", res.Stderr)
	}
	ids := strings.Fields(res.Stdout)
	if len(ids) == 0 {
		fmt.Println("no pilot sandbox containers to prune")
		return nil
	}
	args2 := append([]string{"rm", "-f"}, ids...)
	res, err = dockerCmd(context.Background(), args2...)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("docker rm: %s", res.Stderr)
	}
	fmt.Printf("pruned %d container(s)\n", len(ids))
	return nil
}

var (
	sandboxAttachName string
)

var sandboxAttachCmd = &cobra.Command{
	Use:   "attach [name]",
	Short: "Open an interactive bash shell inside a running sandbox container",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runSandboxAttach,
}

func init() {
	sandboxAttachCmd.Flags().StringVar(&sandboxAttachName, "name", "",
		"container name (default: most recent pilot sandbox)")
}

func runSandboxAttach(cmd *cobra.Command, args []string) error {
	name := sandboxAttachName
	if name == "" && len(args) > 0 {
		name = args[0]
	}
	if name == "" {
		// Pick the most recent running one.
		res, err := dockerCmd(context.Background(),
			"ps", "--filter", "name=pilot-sandbox-",
			"--format", "{{.Names}}\t{{.CreatedAt}}")
		if err != nil {
			return err
		}
		bestName := ""
		var bestTime time.Time
		for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, "\t", 2)
			t, _ := time.Parse("2006-01-02 15:04:05 -0700 MST", parts[1])
			if bestName == "" || t.After(bestTime) {
				bestName = parts[0]
				bestTime = t
			}
		}
		if bestName == "" {
			return fmt.Errorf("no pilot sandbox container running; start one with `pilot run --sandbox`")
		}
		name = bestName
	}
	// docker exec -it <name> bash. We exec directly so the
	// terminal is connected to the user's TTY (cobra subcommand
	// does not have a tty by default).
	c := exec.Command("docker", "exec", "-it", name, "bash")
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

var (
	sandboxSnapshotTag  string
	sandboxSnapshotName string
)

var sandboxSnapshotCmd = &cobra.Command{
	Use:   "snapshot <name>",
	Short: "Commit the current sandbox container state as a new docker image tag",
	Long: `Capture the container's current filesystem state as a
reusable image. After this, 'pilot run --sandbox --sandbox-image <tag>'
starts from this snapshot instead of the original base image.

Typical loop-engineering flow:
  1. pilot run --sandbox --sandbox-keep --sandbox-image ubuntu:22.04
  2. ... iterations converge ...
  3. pilot sandbox snapshot --tag my-baseline
  4. pilot sandbox prune
  5. pilot run --sandbox --sandbox-image my-baseline`,
	Args: cobra.MaximumNArgs(1),
	RunE: runSandboxSnapshot,
}

func init() {
	sandboxSnapshotCmd.Flags().StringVar(&sandboxSnapshotTag, "tag", "",
		"new image tag (required)")
	sandboxSnapshotCmd.Flags().StringVar(&sandboxSnapshotName, "name", "",
		"container name (default: most recent pilot sandbox)")
	_ = sandboxSnapshotCmd.MarkFlagRequired("tag")
}

func runSandboxSnapshot(cmd *cobra.Command, args []string) error {
	name := sandboxSnapshotName
	if name == "" && len(args) > 0 {
		name = args[0]
	}
	if name == "" {
		// pick most recent
		res, err := dockerCmd(context.Background(),
			"ps", "-a", "--filter", "name=pilot-sandbox-",
			"--format", "{{.Names}}\t{{.CreatedAt}}")
		if err != nil {
			return err
		}
		var best string
		var bestT time.Time
		for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, "\t", 2)
			t, _ := time.Parse("2006-01-02 15:04:05 -0700 MST", parts[1])
			if best == "" || t.After(bestT) {
				best = parts[0]
				bestT = t
			}
		}
		if best == "" {
			return fmt.Errorf("no pilot sandbox container found")
		}
		name = best
	}
	res, err := dockerCmd(context.Background(),
		"commit", name, sandboxSnapshotTag)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("docker commit: %s", res.Stderr)
	}
	imageID := strings.TrimSpace(res.Stdout)
	fmt.Printf("snapshotted %s as %s (image id: %s)\n", name, sandboxSnapshotTag, imageID[:12])
	return nil
}

var (
	sandboxRollbackImage string
)

var sandboxRollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Revert a sandbox container to a previously snapshotted image",
	RunE:  runSandboxRollback,
}

func init() {
	sandboxRollbackCmd.Flags().StringVar(&sandboxRollbackImage, "image", "",
		"image tag to roll back to (required)")
	sandboxRollbackCmd.Flags().StringVar(&sandboxAttachName, "name", "",
		"container name (default: most recent pilot sandbox)")
	_ = sandboxRollbackCmd.MarkFlagRequired("image")
}

func runSandboxRollback(cmd *cobra.Command, args []string) error {
	name := sandboxAttachName
	if name == "" {
		return fmt.Errorf("--name required (or pass via positional arg in a future version)")
	}
	// Stop, remove, then start fresh from the given image.
	for _, sub := range [][]string{{"stop", name}, {"rm", "-f", name}} {
		res, err := dockerCmd(context.Background(), sub...)
		if err != nil {
			return err
		}
		_ = res // exit non-zero when container is gone already is fine
	}
	res, err := dockerCmd(context.Background(),
		"run", "-d", "--rm",
		"--name", name,
		"--pull", "never", // local snapshot; don't phone home
		sandboxRollbackImage,
		"tail", "-f", "/dev/null")
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("docker run from snapshot: %s", res.Stderr)
	}
	fmt.Printf("rolled back %s to image %s (new id: %s)\n",
		name, sandboxRollbackImage, strings.TrimSpace(res.Stdout)[:12])
	return nil
}

var (
	sandboxWarmupImage string
)

var sandboxWarmupCmd = &cobra.Command{
	Use:   "warmup",
	Short: "Pre-pull a docker image so the next --sandbox starts instantly",
	RunE:  runSandboxWarmup,
}

func init() {
	sandboxWarmupCmd.Flags().StringVar(&sandboxWarmupImage, "image", "",
		"docker image to pre-pull (required)")
	_ = sandboxWarmupCmd.MarkFlagRequired("image")
}

func runSandboxWarmup(cmd *cobra.Command, args []string) error {
	fmt.Printf("pulling %s ...\n", sandboxWarmupImage)
	res, err := dockerCmd(context.Background(),
		"pull", sandboxWarmupImage)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("docker pull: %s", res.Stderr)
	}
	fmt.Printf("✓ %s ready\n", sandboxWarmupImage)
	return nil
}

var (
	sandboxStatusName string
)

var sandboxStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the running sandbox container's details (image, uptime, changed paths)",
	RunE:  runSandboxStatus,
}

func init() {
	sandboxStatusCmd.Flags().StringVar(&sandboxStatusName, "name", "",
		"container name (default: most recent pilot sandbox)")
}

func runSandboxStatus(cmd *cobra.Command, args []string) error {
	name := sandboxStatusName
	if name == "" {
		res, err := dockerCmd(context.Background(),
			"ps", "--filter", "name=pilot-sandbox-",
			"--format", "{{.Names}}\t{{.CreatedAt}}")
		if err != nil {
			return err
		}
		var best string
		var bestT time.Time
		for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, "\t", 2)
			t, _ := time.Parse("2006-01-02 15:04:05 -0700 MST", parts[1])
			if best == "" || t.After(bestT) {
				best = parts[0]
				bestT = t
			}
		}
		if best == "" {
			return fmt.Errorf("no running pilot sandbox")
		}
		name = best
	}
	// Inspect for image, uptime, mounts.
	inspectRes, err := dockerCmd(context.Background(),
		"inspect",
		"--format", "{{.Config.Image}}\t{{.State.StartedAt}}",
		name)
	if err != nil || inspectRes.ExitCode != 0 {
		return fmt.Errorf("docker inspect: %s", inspectRes.Stderr)
	}
	parts := strings.SplitN(strings.TrimSpace(inspectRes.Stdout), "\t", 2)
	image := parts[0]
	startedAt, _ := time.Parse(time.RFC3339Nano, parts[1])
	uptime := time.Since(startedAt).Round(time.Second)

	// diff for changed files
	diffRes, _ := dockerCmd(context.Background(), "diff", name)
	var changed []string
	for _, line := range strings.Split(diffRes.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= 3 && (line[0] == 'A' || line[0] == 'C' || line[0] == 'D') {
			changed = append(changed, strings.TrimSpace(line[1:]))
		}
	}
	sort.Strings(changed)
	if len(changed) > 20 {
		changed = append(changed[:20], fmt.Sprintf("... (%d more)", len(changed)-20))
	}

	fmt.Printf("┌─ sandbox: %s ─\n", name)
	fmt.Printf("│ image:      %s\n", image)
	fmt.Printf("│ started:    %s (%s ago)\n", startedAt.Format(time.RFC3339), uptime)
	fmt.Printf("│ files changed: %d\n", len(changed))
	for _, p := range changed {
		fmt.Printf("│   %s\n", p)
	}
	fmt.Println("└─────────────────────────────────────────────")
	return nil
}

// dockerCmd is a small wrapper around `docker` so the subcommands
// don't have to repeat the bytes.Buffer plumbing. The same helper
// exists in internal/sandbox/docker.go but we duplicate here so the
// cmd package stays free of sandbox internals (avoids import cycles).
func dockerCmd(ctx context.Context, args ...string) (*dockerResult, error) {
	c, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(c, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := &dockerResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if exitErr, ok := err.(*exec.ExitError); ok {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	if err != nil {
		return res, err
	}
	res.ExitCode = 0
	return res, nil
}

type dockerResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}
