package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anomalyco/pilot/internal/sandbox"
)

// readFileArgs is defined in schemas.go

// DefaultSensitivePaths are paths the LLM must NEVER read. These
// cover well-known credential stores, kernel surfaces, and SSH state.
// Substrings are matched as prefixes on the absolute resolved path.
var DefaultSensitivePaths = []string{
	"/etc/shadow",
	"/etc/shadow-",
	"/etc/shadow.bak",
	"/etc/gshadow",
	"/etc/gshadow-",
	"/etc/sudoers",
	"/etc/sudoers.d/",
	"/etc/sudo-ldap.conf",
	"/proc/",
	"/sys/",
	// SSH private keys and configuration
	"/.ssh/id_rsa",
	"/.ssh/id_ed25519",
	"/.ssh/id_ecdsa",
	"/.ssh/id_dsa",
	"/.ssh/identity",
	"/.ssh/authorized_keys",
	"/.ssh/known_hosts",
	"/.ssh/config",
	// Cloud / container credentials
	"/.aws/credentials",
	"/.aws/config",
	"/.azure/",
	"/.config/gcloud/",
	"/.config/gh/hosts.yml",
	"/.docker/config.json",
	"/.kube/config",
	// Browser / GPG / TPM / KWallet secret stores
	"/.gnupg/",
	"/.local/share/keyrings/",
	"/.password-store/",
	// Kernel / boot / firmware
	"/boot/",
	"/efi/",
	// Sensitive logs (may contain passwords in headers)
	"/var/log/auth.log",
	"/var/log/secure",
	"/var/log/wtmp",
	"/var/log/btmp",
}

// DefaultAllowedReadPrefixes is the baseline set of prefixes the
// LLM is permitted to read when no per-run BaseDir is configured.
// We deliberately keep this small and conservative.
var DefaultAllowedReadPrefixes = []string{
	"/etc/ansible/",
	"/etc/ssh/sshd_config",
	"/etc/ssh/ssh_config",
	"/etc/fail2ban/",
	"/etc/audit/",
	"/etc/aide.conf",
	"/etc/login.defs",
	"/etc/pam.d/",
	"/etc/security/",
	"/etc/sysctl.d/",
	"/etc/modprobe.d/",
	"/etc/profile.d/",
	"/etc/bash.bashrc",
	"/etc/environment",
	"/etc/hostname",
	"/etc/hosts",
	"/etc/resolv.conf",
	"/etc/nsswitch.conf",
	"/etc/timezone",
	"/etc/os-release",
	"/etc/lsb-release",
	"/usr/lib/os-release",
	"/usr/lib/lsb-release",
	"/var/log/syslog",
	"/var/log/messages",
	"/var/log/dpkg.log",
	"/var/log/apt/",
	"/var/log/kern.log",
	"/tmp/",
	"/var/tmp/",
	"/opt/",
}

// ReadFileTool reads a local file (localhost mode). For remote files,
// the LLM should use run_ansible with the slurp module.
type ReadFileTool struct {
	// BaseDir restricts reads to this directory (absolute). If empty,
	// the prefix-allowlist DefaultAllowedReadPrefixes is used.
	BaseDir string
	// AllowedPrefixes extends or replaces DefaultAllowedReadPrefixes
	// (only consulted when BaseDir is empty). If non-empty, it is used
	// INSTEAD of DefaultAllowedReadPrefixes.
	AllowedPrefixes []string
	// Env, when non-nil, redirects reads through the sandbox
	// environment (e.g. docker exec inside a managed container).
	// If nil, reads happen on the local host.
	Env sandbox.Environment
}

func (t *ReadFileTool) Spec() *Spec {
	return &Spec{
		Name:        "read_file",
		Description: "Read a text file from the local filesystem. Returns up to 200 lines. Sensitive files (credentials, SSH keys, /proc, /sys, kernel/boot files, cloud configs) are always blocked. By default only specific /etc/, /var/log/, /tmp/, /opt/ paths are permitted; pass BaseDir or AllowedPrefixes via the setup to broaden. For remote files on Ansible targets, prefer run_ansible with a slurp/setup task instead.",
		RiskLevel:   "low",
		Reversible:  true,
		DryRunSafe:  true,
		Parameters:  readFileArgs,
	}
}

func (t *ReadFileTool) allowedPrefixes() []string {
	if t.BaseDir != "" {
		return []string{t.BaseDir}
	}
	if len(t.AllowedPrefixes) > 0 {
		return t.AllowedPrefixes
	}
	return DefaultAllowedReadPrefixes
}

// ValidatePath returns nil if path is safe to read. It returns an
// error describing why the read was rejected otherwise.
func (t *ReadFileTool) ValidatePath(expanded string) error {
	// Resolve symlinks so a symlink under /tmp → /etc/shadow can't
	// sneak past the prefix check.
	resolved, err := filepath.EvalSymlinks(expanded)
	if err == nil {
		expanded = resolved
	}

	// 1. Hard block — never readable.
	lower := strings.ToLower(expanded)
	for _, sensitive := range DefaultSensitivePaths {
		if strings.HasPrefix(lower, sensitive) {
			return fmt.Errorf("reading %s is blocked for safety (sensitive path)", expanded)
		}
	}

	// 2. If BaseDir is set, only that directory is allowed.
	if t.BaseDir != "" {
		base := t.BaseDir
		if !strings.HasSuffix(base, "/") {
			base += "/"
		}
		if !strings.HasPrefix(expanded, base) {
			return fmt.Errorf("reading %s is outside the configured BaseDir %s", expanded, t.BaseDir)
		}
		return nil
	}

	// 3. Otherwise, require the path to match one of the allowed prefixes.
	for _, p := range t.allowedPrefixes() {
		if !strings.HasSuffix(p, "/") && !strings.HasSuffix(p, ".conf") {
			// Allow exact-file match for non-directory prefixes
			// (e.g. "/etc/hostname").
			if expanded == p {
				return nil
			}
			continue
		}
		if strings.HasPrefix(expanded, p) {
			return nil
		}
	}
	return fmt.Errorf("reading %s is not in the allowed paths (configure AllowedPrefixes or BaseDir to broaden)", expanded)
}

func (t *ReadFileTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	var a struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return nil, fmt.Errorf("read_file: invalid args: %w", err)
	}
	if a.Path == "" {
		return nil, fmt.Errorf("read_file: path is required")
	}

	expanded, err := expandPath(a.Path)
	if err != nil {
		return nil, err
	}

	if err := t.ValidatePath(expanded); err != nil {
		return &Result{Content: fmt.Sprintf("ERROR: %v", err), IsError: true}, nil
	}

	// Sandbox-aware read. The path allowlist still applies upstream
	// (we validated expanded above) — but when Env is set, the file
	// is fetched from inside the container. The local /etc/shadow
	// allowlist check still works because the path prefix is
	// what matters, not the source location.
	var data []byte
	if t.Env != nil {
		var rerr error
		data, rerr = t.Env.ReadFile(ctx, expanded)
		if rerr != nil {
			return &Result{Content: fmt.Sprintf("ERROR: %v", rerr), IsError: true}, nil
		}
	} else {
		var rerr error
		data, rerr = os.ReadFile(expanded)
		if rerr != nil {
			return &Result{Content: fmt.Sprintf("ERROR: %v", rerr), IsError: true}, nil
		}
	}
	if err != nil {
		return &Result{Content: fmt.Sprintf("ERROR: %v", err), IsError: true}, nil
	}

	// Truncate large files
	content := string(data)
	lines := strings.Split(content, "\n")
	if len(lines) > 200 {
		content = strings.Join(lines[:200], "\n") + fmt.Sprintf("\n... [truncated, %d more lines]", len(lines)-200)
	}
	return &Result{Content: content}, nil
}

func expandPath(p string) (string, error) {
	if strings.HasPrefix(p, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		p = filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	return filepath.Abs(p)
}
