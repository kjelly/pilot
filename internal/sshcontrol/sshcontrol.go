// Package sshcontrol owns the private directories pilot points OpenSSH's
// ControlPath at. pilot deploy (one directory per data dir) and vm-target
// (one directory per VM) share it, so the socket-length budget and the
// ownership checks on a world-writable base live in one place.
package sshcontrol

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// BaseEnv overrides the directory the control directories are created in.
// The default is /tmp on purpose, not a data dir or os.TempDir(): a Unix
// socket path must fit in 108 bytes (OpenSSH also appends a 17-byte
// temporary suffix while creating a master), and both a data dir and
// $TMPDIR can be arbitrarily deep. An override must stay short too (for
// example /run/user/<uid>). Tests set it so they and the pilot subprocesses
// they spawn stay out of the real /tmp.
const BaseEnv = "PILOT_SSH_CONTROL_BASE"

// SocketName is the ControlPath file name used inside a control directory:
// %C is OpenSSH's fixed-length (40 hex) hash of the connection tuple, so
// the socket path never grows with the host name.
const SocketName = "%C"

// Base returns the directory control directories are created in.
func Base() string {
	if base := os.Getenv(BaseEnv); base != "" {
		return base
	}
	return "/tmp"
}

// Dir returns the control directory for key without creating it:
// <Base()>/pilot-<kind>-<uid>-<first 4 bytes of sha256(key), hex>. The same
// kind and key always give the same directory; different keys give
// different ones, so one owner never reuses another's authenticated master.
func Dir(kind, key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(Base(), fmt.Sprintf("pilot-%s-%d-%x", kind, os.Getuid(), sum[:4]))
}

// ControlPath returns the ControlPath template for sockets in dir.
func ControlPath(dir string) string {
	return filepath.Join(dir, SocketName)
}

// Ensure creates dir (mode 0700) if it does not exist. The base is
// world-writable, so an existing path is accepted only if it is a real
// directory (not a symlink) owned by this user; group and other permission
// bits are removed. The sticky bit on /tmp stops other users from replacing
// the directory afterwards.
func Ensure(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("create SSH control directory %s: %w", dir, err)
	}
	info, err := checkOwned(dir)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("restrict SSH control directory %s: %w", dir, err)
		}
	}
	return nil
}

// Remove deletes dir and the sockets in it. A missing dir is already
// removed. A path that is not a directory owned by this user is left alone
// and reported, because the base is shared with other users.
func Remove(dir string) error {
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if _, err := checkOwned(dir); err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove SSH control directory %s: %w", dir, err)
	}
	return nil
}

func checkOwned(dir string) (fs.FileInfo, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("inspect SSH control directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("SSH control directory %s is not a directory (%s); remove it and retry", dir, info.Mode().Type())
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		return nil, fmt.Errorf("SSH control directory %s is not owned by uid %d; remove it and retry", dir, os.Getuid())
	}
	return info, nil
}
