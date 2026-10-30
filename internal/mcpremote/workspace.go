package mcpremote

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/kjelly/pilot/internal/mcpwire"
)

// copyTree copies the regular files and directories under src to dst. It
// never follows or copies a symlink.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o700)
		case d.Type().IsRegular():
			return copyFile(p, target)
		default:
			return nil
		}
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// buildWorkspace turns the validated source into the session workspace:
// a private copy, .vault linked to the environment's read-only vault, the
// image's contracts copied in, and (unless disabled) /pilot/config linked
// to it. It returns the directory the MCP server should use as --dir.
func buildWorkspace(cfg *Config, source, work string) (string, error) {
	if err := copyTree(source, work); err != nil {
		return "", errorf(mcpwire.CodeRuntimeError, "copy snapshot: %v", err)
	}
	if err := os.Symlink(cfg.VaultDir, filepath.Join(work, ".vault")); err != nil {
		return "", errorf(mcpwire.CodeRuntimeError, "link .vault: %v", err)
	}
	if err := copyTree(filepath.Join(cfg.PilotRoot, "contracts"), filepath.Join(work, "contracts")); err != nil {
		return "", errorf(mcpwire.CodeRuntimeError, "copy contracts: %v", err)
	}
	return linkConfig(cfg, work)
}

// linkConfig points cfg.ConfigLink at work, replacing only a symlink.
func linkConfig(cfg *Config, work string) (string, error) {
	if cfg.ConfigLink == "" {
		return work, nil
	}
	if info, err := os.Lstat(cfg.ConfigLink); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return "", errorf(mcpwire.CodeRuntimeError, "%s exists and is not a symlink; refusing to replace it", cfg.ConfigLink)
		}
		if err := os.Remove(cfg.ConfigLink); err != nil {
			return "", errorf(mcpwire.CodeRuntimeError, "replace %s: %v", cfg.ConfigLink, err)
		}
	} else if !os.IsNotExist(err) {
		return "", errorf(mcpwire.CodeRuntimeError, "inspect %s: %v", cfg.ConfigLink, err)
	}
	if err := os.Symlink(work, cfg.ConfigLink); err != nil {
		return "", errorf(mcpwire.CodeRuntimeError, "link %s: %v", cfg.ConfigLink, err)
	}
	return cfg.ConfigLink, nil
}

// hashTree returns path -> SHA-256 for the regular files under root,
// skipping symlinks and the .pilot and contracts directories (pilot state
// and the image's catalog, never part of an edit).
func hashTree(root string) (map[string]string, error) {
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == ".pilot" || rel == "contracts" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		sum, err := hashFile(p)
		if err != nil {
			return err
		}
		out[rel] = sum
		return nil
	})
	return out, err
}

func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
