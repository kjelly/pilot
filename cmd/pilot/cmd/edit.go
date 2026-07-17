// edit.go holds the pure data helpers backing `pilot edit` — reading/
// writing hosts.yml (via internal/inventory), scanning group_vars/ and
// .vault/ directories, and detecting ansible-vault-encrypted files.
// None of this depends on a UI: it's exercised directly by
// edit_test.go, and used by the actual wizard screens in edit_tui.go /
// edit_tui_groupvars.go / edit_tui_vault.go (a Bubble Tea router — see
// edit_tui.go's package doc comment for why one continuous
// tea.Program replaces the promptui-driven nested loops this file
// used to contain).
package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/anomalyco/pilot/internal/inventory"
)

// ---- hosts.yml -------------------------------------------------------------

func saveHosts(out io.Writer, path string, hf *inventory.HostsFile) error {
	if issues := inventory.Lint(hf); len(issues) > 0 {
		fmt.Fprintln(out, "ℹ️  存檔前的檢查結果(不會擋存檔，但套用前建議先解決 error)：")
		for _, i := range issues {
			fmt.Fprintf(out, "   %s\n", i)
		}
	}
	rendered, err := inventory.Render(hf)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(rendered), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Fprintf(out, "✅ 已存檔 %s\n", path)
	return nil
}

func hostNames(hf *inventory.HostsFile) []string {
	names := make([]string, len(hf.Hosts))
	for i, h := range hf.Hosts {
		names[i] = h.Name
	}
	return names
}

func hostSummary(hf *inventory.HostsFile, name string) string {
	h := findHost(hf, name)
	if h == nil {
		return name
	}
	host := h.AnsibleHost
	if host == "" {
		host = "(尚未填 ansible_host)"
	}
	roles := "(尚未選角色)"
	if len(h.Roles) > 0 {
		roles = strings.Join(h.Roles, ", ")
	}
	return fmt.Sprintf("%s — %s — %s", name, host, roles)
}

func findHost(hf *inventory.HostsFile, name string) *inventory.Host {
	for i := range hf.Hosts {
		if hf.Hosts[i].Name == name {
			return &hf.Hosts[i]
		}
	}
	return nil
}

func removeHost(hf *inventory.HostsFile, name string) {
	out := hf.Hosts[:0]
	for _, h := range hf.Hosts {
		if h.Name != name {
			out = append(out, h)
		}
	}
	hf.Hosts = out
}

func sortedKeysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func displayOrPlaceholder(s string) string {
	if s == "" {
		return "(未設定)"
	}
	return s
}

// ---- group_vars/*.yml -------------------------------------------------------

// scanGroupVars lists the *.yml files already under targetDir
// (existing) plus the exampleDir/*.example.yml stems that don't have
// a counterpart in targetDir yet (missingExamples) — offered as
// "create from example" menu entries. targetDir and exampleDir are
// often the same path (the default, un-"--dir"'d case) but don't have
// to be. A targetDir that doesn't exist yet just yields no existing
// files, not an error — it may not have been created yet.
func scanGroupVars(targetDir, exampleDir string) (existing []string, missingExamples []string, err error) {
	haveYML := map[string]bool{}
	if entries, err := os.ReadDir(targetDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".example.yml") {
				haveYML[strings.TrimSuffix(name, ".yml")] = true
				existing = append(existing, name)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("read %s: %w", targetDir, err)
	}
	sort.Strings(existing)

	haveExample := map[string]bool{}
	if entries, err := os.ReadDir(exampleDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if name := e.Name(); strings.HasSuffix(name, ".example.yml") {
				haveExample[strings.TrimSuffix(name, ".example.yml")] = true
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("read %s: %w", exampleDir, err)
	}

	for stem := range haveExample {
		if !haveYML[stem] {
			missingExamples = append(missingExamples, stem)
		}
	}
	sort.Strings(missingExamples)
	return existing, missingExamples, nil
}

// ---- .vault/*.yaml ---------------------------------------------------------

func scanVaultFiles(targetDir string) ([]string, error) {
	var files []string
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", targetDir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files, nil
}

func isAnsibleVaultEncrypted(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(data), []byte("$ANSIBLE_VAULT;"))
}

// runAnsibleVaultEditSync shells out to the real `ansible-vault edit`
// with stdio wired directly to the terminal. It must never be called
// while a tea.Program is running (it would fight the Program for
// control of the terminal) — the vault-editing wizard flow instead
// calls this via tea.ExecProcess, which suspends the Program first;
// see edit_tui_vault.go.
func runAnsibleVaultEditSync(path string) error {
	bin, err := exec.LookPath("ansible-vault")
	if err != nil {
		return fmt.Errorf("ansible-vault 不在 PATH 上: %w", err)
	}
	cmd := exec.Command(bin, "edit", path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ansible-vault edit %s: %w", path, err)
	}
	return nil
}
