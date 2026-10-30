// Package mcpremote is `pilot mcp remote`: it runs inside the pilot-cli
// container that pilot-mcp starts with one `docker run` over SSH. A
// session reads the configuration snapshot from stdin, validates it,
// builds a private workspace with the environment's read-only .vault, then
// serves the existing pilot MCP server on the rest of stdin/stdout.
//
// Spec: docs/superpowers/specs/2026-10-30-pilot-mcp-remote-access-spec.md §6-§7.
package mcpremote

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/kjelly/pilot/internal/mcpwire"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Error carries one of the mcpwire error codes.
type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string { return e.Code + ": " + e.Err.Error() }

func (e *Error) Unwrap() error { return e.Err }

func errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Err: fmt.Errorf(format, args...)}
}

// CodeOf returns err's mcpwire code, or RUNTIME_ERROR for an untyped error.
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return mcpwire.CodeRuntimeError
}

// ServeOptions is what the injected Serve callback needs to start the
// pilot MCP server (cmd/pilot/cmd's serveMCP) for one session.
type ServeOptions struct {
	Dir               string
	AuditDir          string
	DiagnoseInventory string
	AllowWrite        bool
	Transport         mcp.Transport
}

// Config is one `pilot mcp remote` invocation. cmd/pilot/cmd fills the
// paths (container defaults, or test overrides) and injects the two
// callbacks that live in cmd/pilot/cmd, which this package cannot import.
type Config struct {
	Mode string
	Env  string

	VaultDir   string // read-only .vault of Env
	DataDir    string // Env's pilot data dir
	TmpDir     string // observe sessions
	PilotRoot  string // image root holding contracts/ and group_vars/
	ConfigLink string // symlink to the workspace; "" serves the work dir directly

	MaxSessionDuration time.Duration

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Now    func() time.Time

	// GenerateInventory runs pilot's inventory generation for the
	// workspace at configDir (writing configDir/inventory.yml).
	GenerateInventory func(configDir string, stderr io.Writer) error
	// Serve runs the pilot MCP server until the client disconnects.
	Serve func(ctx context.Context, opts ServeOptions) error
}

func (c *Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// sessionsRoot holds edit sessions inside the data dir.
func (c *Config) sessionsRoot() string {
	return filepath.Join(c.DataDir, mcpwire.DataMCPDir, "sessions")
}

// auditDir is the --audit-dir every session uses.
func (c *Config) auditDir() string {
	return filepath.Join(c.DataDir, mcpwire.DataMCPDir, "audit")
}

func newSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// BinarySHA256 hashes the running pilot binary, so a session can tell when
// a different image serves it.
func BinarySHA256() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	f, err := os.Open(exe)
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

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
