package mcpwire

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SnapshotHeaderPrefix starts the line pilot-mcp writes before the tar.
const SnapshotHeaderPrefix = "PILOT-MCP-SNAPSHOT "

// ReadyPrefix starts the line pilot mcp remote writes before MCP bytes.
const ReadyPrefix = "PILOT-MCP-READY "

var headerPattern = regexp.MustCompile(`^PILOT-MCP-SNAPSHOT ([0-9]{1,9})\n$`)

// SnapshotHeader is the header line announcing an n-byte tar.
func SnapshotHeader(n int64) string { return fmt.Sprintf("%s%d\n", SnapshotHeaderPrefix, n) }

// ParseSnapshotHeader parses a header line, including its newline, and
// enforces MaxStreamBytes.
func ParseSnapshotHeader(line string) (int64, error) {
	m := headerPattern.FindStringSubmatch(line)
	if m == nil {
		return 0, fmt.Errorf("malformed snapshot header")
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("malformed snapshot header")
	}
	if n > MaxStreamBytes {
		return 0, fmt.Errorf("snapshot of %d bytes exceeds %d: %w", n, MaxStreamBytes, ErrStreamTooLarge)
	}
	return n, nil
}

// ErrStreamTooLarge marks a snapshot header announcing more than
// MaxStreamBytes.
var ErrStreamTooLarge = errors.New("snapshot stream too large")

// Ready is the JSON carried by the ready line.
type Ready struct {
	Protocol          string `json:"protocol"`
	SessionID         string `json:"session_id"`
	Mode              string `json:"mode"`
	Env               string `json:"env"`
	CommitSHA         string `json:"commit_sha"`
	ContentDigest     string `json:"content_digest"`
	Files             int    `json:"files"`
	PilotBinarySHA256 string `json:"pilot_binary_sha256"`
}

// FormatReady renders the ready line, including its newline.
func FormatReady(r Ready) (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return ReadyPrefix + string(data) + "\n", nil
}

// ParseReady parses a ready line with or without its trailing newline.
func ParseReady(line string) (Ready, error) {
	body, ok := strings.CutPrefix(strings.TrimRight(line, "\r\n"), ReadyPrefix)
	if !ok {
		return Ready{}, fmt.Errorf("not a ready line")
	}
	var r Ready
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		return Ready{}, fmt.Errorf("malformed ready line: %w", err)
	}
	if r.Protocol != Protocol {
		return Ready{}, fmt.Errorf("unsupported protocol %q", r.Protocol)
	}
	return r, nil
}

// Version is what `pilot mcp remote version` prints.
type Version struct {
	Protocol          string `json:"protocol"`
	PilotBinarySHA256 string `json:"pilot_binary_sha256"`
}
