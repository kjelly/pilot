package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/manifoldco/promptui"
)

type VaultEncryptStringTool struct {
	AllowedPlaybookRoots []string
	Asker                func(string, []string) string
}

func (t *VaultEncryptStringTool) Spec() *Spec {
	return &Spec{
		Name:        "vault_encrypt_string",
		Description: "Encrypt a plaintext secret using ansible-vault. Returns the encrypted YAML block (e.g. '!vault | ...') that can be pasted directly into variables or playbooks.",
		RiskLevel:   "low",
		Reversible:  true,
		DryRunSafe:  true,
		Parameters:  vaultEncryptArgs,
	}
}

func (t *VaultEncryptStringTool) ValidatePath(path string) error {
	if path == "" {
		return nil
	}
	roots := t.AllowedPlaybookRoots
	if len(roots) == 0 {
		roots = DefaultAllowedPlaybookRoots
	}
	if len(roots) == 0 {
		return fmt.Errorf("vault_password_file path %q rejected: no allowed roots configured", path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("vault_password_file path %q rejected: %v", path, err)
	}
	if rl, err := filepath.EvalSymlinks(abs); err == nil {
		abs = rl
	}
	for _, root := range roots {
		rootAbs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		if !strings.HasSuffix(rootAbs, "/") {
			rootAbs += "/"
		}
		if strings.HasPrefix(abs, rootAbs) {
			return nil
		}
	}
	return fmt.Errorf("vault_password_file path %q (resolved %s) is outside the allowed roots %v", path, abs, roots)
}

func (t *VaultEncryptStringTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	var a struct {
		Plaintext         string `json:"plaintext"`
		Name              string `json:"name"`
		VaultPasswordFile string `json:"vault_password_file"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return nil, fmt.Errorf("vault_encrypt_string: invalid args: %w", err)
	}
	if a.Plaintext == "" || a.Name == "" {
		return nil, fmt.Errorf("vault_encrypt_string: plaintext and name are required")
	}

	var password string
	if a.VaultPasswordFile != "" {
		if err := t.ValidatePath(a.VaultPasswordFile); err != nil {
			return &Result{Content: fmt.Sprintf("ERROR: %v", err), IsError: true}, nil
		}
	} else {
		// Prompt user interactively
		if t.Asker != nil {
			password = t.Asker("請輸入 Ansible Vault 密碼以加密變數 (輸入將被遮蔽/不顯示):", nil)
		} else {
			prompt := promptui.Prompt{
				Label: "請輸入 Ansible Vault 密碼以加密變數",
				Mask:  '*',
			}
			var err error
			password, err = prompt.Run()
			if err != nil {
				return &Result{Content: fmt.Sprintf("ERROR: failed to read vault password: %v", err), IsError: true}, nil
			}
		}
		if password == "" {
			return &Result{Content: "ERROR: vault password cannot be empty", IsError: true}, nil
		}
	}

	bin, err := exec.LookPath("ansible-vault")
	if err != nil {
		return &Result{Content: "ERROR: ansible-vault not found in PATH", IsError: true}, nil
	}

	var tempVaultFile string
	if password != "" {
		tmpFile, err := os.CreateTemp("", "pilot-vault-pwd-*")
		if err != nil {
			return &Result{Content: fmt.Sprintf("ERROR: failed to create temporary vault password file: %v", err), IsError: true}, nil
		}
		_ = tmpFile.Chmod(0o600)
		if _, err := tmpFile.WriteString(password); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return &Result{Content: fmt.Sprintf("ERROR: failed to write temporary vault password file: %v", err), IsError: true}, nil
		}
		tmpFile.Close()
		tempVaultFile = tmpFile.Name()
		defer os.Remove(tempVaultFile)
	}

	vaultFile := a.VaultPasswordFile
	if tempVaultFile != "" {
		vaultFile = tempVaultFile
	}

	cmdArgs := []string{"encrypt_string", a.Plaintext, "--name", a.Name}
	if vaultFile != "" {
		cmdArgs = append(cmdArgs, "--vault-password-file", vaultFile)
	} else {
		return &Result{Content: "ERROR: vault_password_file or interactive password is required for encrypting secrets", IsError: true}, nil
	}

	cmd := exec.CommandContext(ctx, bin, cmdArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return &Result{Content: fmt.Sprintf("ERROR: ansible-vault failed: %v\nOutput: %s", err, string(out)), IsError: true}, nil
	}

	return &Result{Content: string(out)}, nil
}
