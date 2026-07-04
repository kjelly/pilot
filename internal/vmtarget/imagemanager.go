package vmtarget

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// DefaultOSImages maps OS names to their official cloud image download URLs.
var DefaultOSImages = map[string]string{
	"ubuntu-24.04":    "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img",
	"ubuntu-22.04":    "https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img",
	"fedora-40":       "https://download.fedoraproject.org/pub/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2",
	"almalinux-9":     "https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2",
	"centos-9":        "https://cloud.centos.org/centos/9-stream/x86_64/images/CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2",
	"centos-stream-9": "https://cloud.centos.org/centos/9-stream/x86_64/images/CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2",
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
			// Preflight: virt-customize (libguestfs) runs as the invoking user
			// and needs /dev/kvm for hardware acceleration. Without it, it
			// silently falls back to software emulation (TCG) and crawls. Print
			// an actionable fix before libguestfs buries it under its own noisy
			// warning.
			if hint := KVMAccessHint(); hint != "" {
				fmt.Printf("warning: %s\n", hint)
			}
			if hint := ApplianceDHCPHint(); hint != "" {
				fmt.Printf("warning: %s\n", hint)
			}
			// Cloud images ship /etc/resolv.conf as a symlink into
			// /run/systemd/..., which dangles inside the libguestfs
			// appliance chroot — --install then fails DNS resolution
			// even though the appliance network is up. Swap in a real
			// resolver for the duration and restore the original
			// (file, symlink, or absence) exactly afterwards.
			cmd := exec.CommandContext(ctx, "virt-customize",
				"-a", goldenTmp,
				"--run-command", `if [ -e /etc/resolv.conf ] || [ -L /etc/resolv.conf ]; then mv /etc/resolv.conf /etc/resolv.conf.pilot-saved; fi; printf 'nameserver 8.8.8.8\nnameserver 1.1.1.1\n' > /etc/resolv.conf`,
				"--install", "python3,sudo,curl,net-tools,systemd",
				"--run-command", "systemctl disable apt-daily.timer apt-daily-upgrade.timer || true",
				"--run-command", `rm -f /etc/resolv.conf; if [ -e /etc/resolv.conf.pilot-saved ] || [ -L /etc/resolv.conf.pilot-saved ]; then mv /etc/resolv.conf.pilot-saved /etc/resolv.conf; fi`,
			)
			env, envErr := virtCustomizeEnv(imageDir)
			if envErr != nil {
				fmt.Printf("warning: %v (continuing with default appliance network)\n", envErr)
			}
			cmd.Env = env
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

// ApplianceDHCPHint returns an actionable remediation string when the host
// lacks dhclient (package isc-dhcp-client). The libguestfs appliance is
// assembled by supermin from packages installed on the host, and its package
// list requests isc-dhcp-client specifically — on hosts without it (Ubuntu
// 24.04 replaced it with dhcpcd-base, which supermin does NOT pick up) the
// appliance boots with no DHCP client at all, eth0 stays down, and every
// virt-customize --install fails with DNS errors after minutes of booting.
func ApplianceDHCPHint() string {
	if _, err := exec.LookPath("dhclient"); err == nil {
		return ""
	}
	// PATH may omit /usr/sbin for non-login shells; check the usual spots
	// before concluding it is absent.
	for _, p := range []string{"/usr/sbin/dhclient", "/sbin/dhclient"} {
		if _, err := os.Stat(p); err == nil {
			return ""
		}
	}
	return "'dhclient' (package isc-dhcp-client) is not installed on the host — the libguestfs\n" +
		"         appliance will have no DHCP client, so package installs inside virt-customize\n" +
		"         will fail with DNS errors. fix: sudo apt install isc-dhcp-client"
}

// virtCustomizeEnv builds the environment for virt-customize with two
// adjustments that make the libguestfs appliance network actually work:
//
//  1. XDG_RUNTIME_DIR is removed. Ubuntu's AppArmor profile for passt
//     (the libguestfs network backend since 1.52) only allows writes under
//     /tmp and $HOME, but libguestfs places passt's socket/pid under
//     $XDG_RUNTIME_DIR — passt then exits 1 and the whole customize fails.
//     Without the variable, libguestfs falls back to /tmp, which the
//     profile permits.
//
//  2. A directory containing a stub `passt` that always fails is prepended
//     to PATH. Even once passt starts, the snapshot Ubuntu 24.04 ships
//     (0.0~git20240220) never answers the appliance's DHCP requests, so
//     eth0 gets no address and every download fails with DNS errors.
//     libguestfs probes `passt --help` to pick the backend; making the
//     probe fail steers it to qemu's built-in SLIRP (-netdev user), which
//     works. Delete the stub dir (or fix passt) to re-enable passt.
func virtCustomizeEnv(stateDir string) ([]string, error) {
	env := environWithout("XDG_RUNTIME_DIR")

	shimDir := filepath.Join(stateDir, ".no-passt")
	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		return env, fmt.Errorf("vmtarget: create passt-shim dir: %w", err)
	}
	stub := filepath.Join(shimDir, "passt")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 127\n"), 0o755); err != nil {
		return env, fmt.Errorf("vmtarget: write passt stub: %w", err)
	}
	for i, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			env[i] = "PATH=" + shimDir + string(os.PathListSeparator) + kv[len("PATH="):]
			return env, nil
		}
	}
	env = append(env, "PATH="+shimDir)
	return env, nil
}

// environWithout returns os.Environ() minus the named variable.
func environWithout(name string) []string {
	prefix := name + "="
	env := os.Environ()
	out := env[:0]
	for _, kv := range env {
		if !strings.HasPrefix(kv, prefix) {
			out = append(out, kv)
		}
	}
	return out
}

// KVMAccessHint returns an actionable remediation string when the current
// process cannot access /dev/kvm, which forces libguestfs/virt-customize into
// slow software emulation (TCG). It returns "" when /dev/kvm is usable — or
// when it is simply absent (no VT-x/AMD-V or nested virt off), a case where
// group advice would be misleading and libguestfs's own message is clearer.
//
// The definitive test is opening the device for read/write, exactly what
// libguestfs does. This also correctly catches the "just ran usermod -aG kvm
// but haven't re-logged-in yet" case, where group membership looks fixed on
// disk but the running process still lacks it.
func KVMAccessHint() string {
	const dev = "/dev/kvm"
	if f, err := os.OpenFile(dev, os.O_RDWR, 0); err == nil {
		_ = f.Close()
		return ""
	} else if !os.IsPermission(err) {
		// Not-exist or any other error: no clean group advice to give.
		return ""
	}

	// Permission denied — name the owning group precisely so the fix is exact.
	grpName := "kvm"
	if fi, err := os.Stat(dev); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			if g, err := user.LookupGroupId(strconv.FormatUint(uint64(st.Gid), 10)); err == nil && g.Name != "" {
				grpName = g.Name
			}
		}
	}
	who := "$USER"
	if u, err := user.Current(); err == nil && u.Username != "" {
		who = u.Username
	}
	return fmt.Sprintf(
		"current user cannot access %s — virt-customize will run WITHOUT KVM acceleration (very slow).\n"+
			"         fix: add your user to the %q group, then re-login (or run 'newgrp %s' in this shell):\n"+
			"              sudo usermod -aG %s %s",
		dev, grpName, grpName, grpName, who)
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
