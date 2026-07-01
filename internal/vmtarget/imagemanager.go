package vmtarget

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DefaultOSImages maps OS names to their official cloud image download URLs.
var DefaultOSImages = map[string]string{
	"ubuntu-24.04": "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img",
	"ubuntu-22.04": "https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img",
}

// PrepareBaseImage ensures that a base qcow2 image is available. If the requested
// image matches a default OS name (e.g. "ubuntu-24.04") or is empty (defaulting to "ubuntu-24.04"),
// it downloads the official cloud image if not present and customizes it to create a
// golden image with pre-installed python3/sudo.
func (m *Manager) PrepareBaseImage(ctx context.Context, nameOrPath string) (string, error) {
	if nameOrPath == "" {
		return "", fmt.Errorf("vmtarget: base image is required")
	}

	// If it's a direct local file path that exists, use it directly.
	if _, err := os.Stat(nameOrPath); err == nil {
		return filepath.Abs(nameOrPath)
	}

	// Resolve default OS alias
	url, exists := DefaultOSImages[strings.ToLower(nameOrPath)]
	if !exists {
		// If it's not a known OS name and does not exist locally, return error
		return "", fmt.Errorf("vmtarget: base image %q not found locally and is not a known OS alias", nameOrPath)
	}

	// Prepare directories
	imageDir := filepath.Join(m.vmDir, "images")
	if err := os.MkdirAll(imageDir, 0o755); err != nil {
		return "", fmt.Errorf("vmtarget: failed to create image cache directory: %w", err)
	}

	rawName := fmt.Sprintf("%s-raw.qcow2", nameOrPath)
	rawPath := filepath.Join(imageDir, rawName)

	goldenName := fmt.Sprintf("%s-golden.qcow2", nameOrPath)
	goldenPath := filepath.Join(imageDir, goldenName)

	// Step 1: Download raw image if missing
	if _, err := os.Stat(rawPath); os.IsNotExist(err) {
		fmt.Printf("▶ downloading official cloud image for %s...\n", nameOrPath)
		if err := downloadFile(ctx, url, rawPath); err != nil {
			return "", fmt.Errorf("vmtarget: failed to download cloud image: %w", err)
		}
		fmt.Println("✓ Download complete.")
	}

	// Step 2: Create/Customize golden image if missing
	if _, err := os.Stat(goldenPath); os.IsNotExist(err) {
		fmt.Printf("▶ customizing %s cloud image to create golden image...\n", nameOrPath)
		// Copy raw to golden first
		if err := copyFile(rawPath, goldenPath); err != nil {
			return "", fmt.Errorf("vmtarget: failed to copy raw image to golden image path: %w", err)
		}

		// Try to run virt-customize if available
		if _, err := exec.LookPath("virt-customize"); err == nil {
			cmd := exec.CommandContext(ctx, "virt-customize",
				"-a", goldenPath,
				"--install", "python3,sudo,curl,net-tools,systemd",
				"--run-command", "systemctl disable apt-daily.timer apt-daily-upgrade.timer || true",
			)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			fmt.Println("▶ running virt-customize to pre-install dependencies...")
			if err := cmd.Run(); err != nil {
				// If customization fails, warning but fallback to the raw image
				fmt.Printf("warning: virt-customize failed: %v. Falling back to uncustomized image.\n", err)
				_ = os.Remove(goldenPath)
				return rawPath, nil
			}
			fmt.Println("✓ Golden image customized successfully.")
		} else {
			fmt.Println("warning: 'virt-customize' not found in PATH. Install 'libguestfs-tools' to pre-bake python3 into the image.")
			fmt.Println("warning: falling back to uncustomized cloud image (python3 will be installed via cloud-init which is slower).")
			// Remove the empty/incomplete golden image copy so it retries next time, and use the raw
			_ = os.Remove(goldenPath)
			return rawPath, nil
		}
	}

	return goldenPath, nil
}

func downloadFile(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
