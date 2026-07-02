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

	// Serialize the download/customize of the shared cache files so two
	// concurrent Up calls in the same process don't race on the same
	// raw/golden paths. (Cross-process safety comes from the atomic
	// tmp+rename in downloadFile and the golden-tmp rename below.)
	m.imgMu.Lock()
	defer m.imgMu.Unlock()

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

	// Step 2: Create/Customize golden image if missing.
	//
	// Build at a temp path and rename into place only on success, so an
	// interrupted virt-customize (killed process, ctx cancel, crash) never
	// leaves a half-baked golden image that the next run would Stat and
	// trust. Same reasoning as the atomic download above.
	if _, err := os.Stat(goldenPath); os.IsNotExist(err) {
		fmt.Printf("▶ customizing %s cloud image to create golden image...\n", nameOrPath)
		goldenTmp := goldenPath + ".tmp"
		_ = os.Remove(goldenTmp)
		// Copy raw to the temp golden path first.
		if err := copyFile(rawPath, goldenTmp); err != nil {
			_ = os.Remove(goldenTmp)
			return "", fmt.Errorf("vmtarget: failed to copy raw image to golden image path: %w", err)
		}

		// Try to run virt-customize if available
		if _, err := exec.LookPath("virt-customize"); err == nil {
			cmd := exec.CommandContext(ctx, "virt-customize",
				"-a", goldenTmp,
				"--install", "python3,sudo,curl,net-tools,systemd",
				"--run-command", "systemctl disable apt-daily.timer apt-daily-upgrade.timer || true",
			)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			fmt.Println("▶ running virt-customize to pre-install dependencies...")
			if err := cmd.Run(); err != nil {
				// If customization fails, warning but fallback to the raw image
				fmt.Printf("warning: virt-customize failed: %v. Falling back to uncustomized image.\n", err)
				_ = os.Remove(goldenTmp)
				return rawPath, nil
			}
			fmt.Println("✓ Golden image customized successfully.")
		} else {
			fmt.Println("warning: 'virt-customize' not found in PATH. Install 'libguestfs-tools' to pre-bake python3 into the image.")
			fmt.Println("warning: falling back to uncustomized cloud image (python3 will be installed via cloud-init which is slower).")
			// Discard the temp copy and use the raw image.
			_ = os.Remove(goldenTmp)
			return rawPath, nil
		}

		// Atomically publish the finished golden image.
		if err := os.Rename(goldenTmp, goldenPath); err != nil {
			_ = os.Remove(goldenTmp)
			return "", fmt.Errorf("vmtarget: finalize golden image: %w", err)
		}
	}

	return goldenPath, nil
}

// downloadFile fetches url to dest atomically: it streams into a temp file
// in the same directory and renames into place only after a fully verified
// transfer. This is deliberate — a partial download (interrupted transfer,
// killed process, ctx cancel) must NEVER be left at dest, because the next
// run Stats dest, finds it, and would treat the truncated file as a complete
// cloud image (a boot failure with no obvious cause).
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

	tmp, err := os.CreateTemp(filepath.Dir(dest), ".download-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	n, err := io.Copy(tmp, resp.Body)
	if err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// If the server declared a length, insist we received all of it — this
	// catches a connection dropped mid-transfer, which io.Copy reports as a
	// clean EOF.
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		return fmt.Errorf("short download: got %d bytes, want %d", n, resp.ContentLength)
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return err
	}
	committed = true
	return nil
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
