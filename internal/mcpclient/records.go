package mcpclient

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Record is one line of sessions.jsonl.
type Record struct {
	Time          time.Time `json:"time"`
	Profile       string    `json:"profile"`
	Env           string    `json:"env"`
	Image         string    `json:"image"`
	Mode          string    `json:"mode"`
	SessionID     string    `json:"session_id"`
	CommitSHA     string    `json:"commit_sha"`
	ContentDigest string    `json:"content_digest"`
}

// DefaultStatePath is $XDG_STATE_HOME/pilot-mcp/sessions.jsonl, falling
// back to ~/.local/state.
func DefaultStatePath() (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "pilot-mcp", "sessions.jsonl"), nil
}

func appendRecord(path string, r Record) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ReadRecords returns the recorded sessions, oldest first, optionally only
// those of one profile. Unreadable lines are skipped.
func ReadRecords(path, profile string) ([]Record, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r Record
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			continue
		}
		if profile == "" || r.Profile == profile {
			out = append(out, r)
		}
	}
	return out, sc.Err()
}
