// Package mcpwire holds what pilot-mcp (the client) and pilot mcp remote
// (inside the pilot-cli container) must agree on byte for byte: container
// paths, the snapshot manifest and its digest, the stdin/stdout framing,
// error lines and the tool names each mode exposes. It imports nothing
// Linux-only, so cmd/pilot-mcp builds for darwin.
//
// Spec: docs/superpowers/specs/2026-10-30-pilot-mcp-remote-access-spec.md.
package mcpwire

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// Protocol identifies this wire format in manifests and ready lines.
const Protocol = "pilot-mcp-remote/v1"

// ProtocolFlag is the value of `pilot mcp remote --protocol`.
const ProtocolFlag = "v1"

// Container paths. pilot-mcp builds the docker run mounts from them and
// pilot mcp remote reads from them, so both sides use these constants.
const (
	// ContainerPilotBinary is the pilot binary inside the pilot-cli image.
	ContainerPilotBinary = "/usr/local/bin/pilot"
	// ContainerPilotRoot is the image's WORKDIR, holding contracts/ and group_vars/.
	ContainerPilotRoot = "/pilot"
	// ContainerVaultDir is where one environment's .vault is mounted read-only.
	ContainerVaultDir = "/pilot/vault"
	// ContainerDataDir is where one environment's .pilot-data is mounted.
	ContainerDataDir = "/pilot/data"
	// ContainerConfigLink is the symlink to the session workspace, matching
	// the /pilot/config paths the Deploy workflow uses.
	ContainerConfigLink = "/pilot/config"
	// ContainerTmpDir holds observe sessions; it disappears with the container.
	ContainerTmpDir = "/tmp/pilot-mcp"
)

// DataMCPDir is the directory, relative to the data dir, holding MCP state.
const DataMCPDir = "mcp"

// Limits on an uploaded snapshot.
const (
	MaxFileBytes     = 8 << 20
	MaxTotalBytes    = 64 << 20
	MaxFiles         = 10000
	MaxStreamBytes   = 80 << 20
	MaxManifestBytes = 1 << 20
	MaxHeaderLine    = 64
)

// Modes and environments.
const (
	ModeObserve = "observe"
	ModeEdit    = "edit"
)

// Envs lists the environment names pilot's inventory accepts.
var Envs = []string{"sandbox", "staging", "prod"}

// ValidEnv reports whether env is one of Envs.
func ValidEnv(env string) bool {
	for _, e := range Envs {
		if env == e {
			return true
		}
	}
	return false
}

// ValidMode reports whether mode is observe or edit.
func ValidMode(mode string) bool { return mode == ModeObserve || mode == ModeEdit }

var sessionIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidSessionID reports whether id is 32 lowercase hex characters.
func ValidSessionID(id string) bool { return sessionIDPattern.MatchString(id) }

// ReservedDirs are top-level directories a snapshot never carries: secrets
// and pilot state come from the deploy node, contracts from the image.
var ReservedDirs = []string{".vault", ".pilot", ".pilot-data", "contracts", ".git"}

// IsReserved reports whether a clean relative path is a reserved directory
// or lies under one.
func IsReserved(p string) bool {
	top, _, _ := strings.Cut(p, "/")
	for _, r := range ReservedDirs {
		if top == r {
			return true
		}
	}
	return false
}

// CheckSnapshotPath validates one file path inside a snapshot or changeset:
// relative, already clean, no "..", backslash, NUL or control characters,
// and not reserved.
func CheckSnapshotPath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") {
		return fmt.Errorf("path %q must be relative", p)
	}
	if path.Clean(p) != p || p == "." {
		return fmt.Errorf("path %q is not clean", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return fmt.Errorf("path %q contains a parent-directory segment", p)
		}
	}
	for _, r := range p {
		if r == '\\' || r < 0x20 || r == 0x7f {
			return fmt.Errorf("path %q contains a backslash or control character", p)
		}
	}
	if IsReserved(p) {
		return fmt.Errorf("path %q is under a reserved directory", p)
	}
	return nil
}
