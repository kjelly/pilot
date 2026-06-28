package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// InspectExistingContainer returns the image of a running (or
// stopped) container with the given name. This is the auto-detect
// path for sandbox mode: the user has a pre-existing container
// named after an inventory host, and pilot derives the image from
// it instead of requiring an explicit --sandbox-image.
//
// Returns an error if:
//   - docker CLI is missing
//   - no container with that name exists
//   - the container exists but has no .Config.Image (very unusual)
func InspectExistingContainer(ctx context.Context, cli, name string) (string, error) {
	bin := cli
	if bin == "" {
		bin = "docker"
	}
	cliPath, err := exec.LookPath(bin)
	if err != nil {
		return "", fmt.Errorf("docker CLI %q not found: %w", bin, err)
	}

	cmd := exec.CommandContext(ctx, cliPath, "inspect",
		"--format", "{{.Config.Image}}",
		name,
	)
	out, err := cmd.Output()
	if err != nil {
		// `docker inspect` exits non-zero with a "No such object" message
		// when the container doesn't exist. Surface a clean error.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			stderr := string(exitErr.Stderr)
			if strings.Contains(stderr, "No such object") ||
				strings.Contains(stderr, "Error: No such container") {
				return "", fmt.Errorf("no container named %q", name)
			}
			return "", fmt.Errorf("docker inspect %q: %s", name, stderr)
		}
		return "", fmt.Errorf("docker inspect %q: %w", name, err)
	}

	image := strings.TrimSpace(string(out))
	if image == "" {
		return "", fmt.Errorf("container %q has empty .Config.Image", name)
	}
	return image, nil
}

// IsImageCached returns true if the given image is present in the
// local docker image cache. Used to short-circuit pull decisions.
func IsImageCached(ctx context.Context, cli, image string) (bool, error) {
	bin := cli
	if bin == "" {
		bin = "docker"
	}
	cliPath, err := exec.LookPath(bin)
	if err != nil {
		return false, err
	}
	cmd := exec.CommandContext(ctx, cliPath, "image", "inspect",
		image, "--format", "{{.Id}}")
	if err := cmd.Run(); err != nil {
		return false, nil
	}
	return true, nil
}
