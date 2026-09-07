// Package diagnosesession stores bounded, append-only correlation evidence for
// multi-call MCP investigations. It records summaries and hashes, never raw
// command output or credentials.
package diagnosesession

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	maxEvents       = 200
	maxSummaryBytes = 4096
)

var validID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type Event struct {
	Seq     int       `json:"seq"`
	At      time.Time `json:"at"`
	Tool    string    `json:"tool"`
	Summary string    `json:"summary,omitempty"`
}

type Record struct {
	ID        string    `json:"id"`
	Subject   string    `json:"subject,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Events    []Event   `json:"events"`
	Truncated bool      `json:"truncated,omitempty"`
}

var processMu sync.Mutex

func Start(root, requestedID, subject string) (Record, error) {
	if root == "" {
		return Record{}, errors.New("diagnosis session root is required")
	}
	id := requestedID
	if id == "" {
		var err error
		id, err = newID()
		if err != nil {
			return Record{}, err
		}
	}
	if !validID.MatchString(id) {
		return Record{}, fmt.Errorf("invalid investigation session id %q", id)
	}
	dir := sessionDir(root, id)
	processMu.Lock()
	defer processMu.Unlock()
	if _, err := os.Stat(dir); err == nil {
		return getUnlocked(root, id)
	} else if !os.IsNotExist(err) {
		return Record{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Record{}, fmt.Errorf("create diagnosis session: %w", err)
	}
	now := time.Now().UTC()
	rec := Record{ID: id, Subject: truncate(subject), CreatedAt: now, UpdatedAt: now, Events: []Event{}}
	if err := writeJSONExclusive(filepath.Join(dir, "session.json"), rec); err != nil {
		return Record{}, err
	}
	return rec, nil
}

func Append(root, id, tool, summary string) (Record, error) {
	if !validID.MatchString(id) {
		return Record{}, fmt.Errorf("invalid investigation session id %q", id)
	}
	if strings.TrimSpace(tool) == "" {
		return Record{}, errors.New("diagnosis session tool is required")
	}
	processMu.Lock()
	defer processMu.Unlock()
	rec, err := getUnlocked(root, id)
	if err != nil {
		return Record{}, err
	}
	if len(rec.Events) >= maxEvents {
		return rec, fmt.Errorf("diagnosis session %q reached the %d-event bound", id, maxEvents)
	}
	event := Event{Seq: len(rec.Events) + 1, At: time.Now().UTC(), Tool: truncate(tool), Summary: truncate(summary)}
	f, err := os.OpenFile(filepath.Join(sessionDir(root, id), "events.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return rec, fmt.Errorf("open diagnosis session events: %w", err)
	}
	data, marshalErr := json.Marshal(event)
	if marshalErr == nil {
		_, marshalErr = f.Write(append(data, '\n'))
	}
	closeErr := f.Close()
	if marshalErr != nil {
		return rec, fmt.Errorf("append diagnosis session event: %w", marshalErr)
	}
	if closeErr != nil {
		return rec, fmt.Errorf("close diagnosis session events: %w", closeErr)
	}
	rec.Events = append(rec.Events, event)
	rec.UpdatedAt = event.At
	if err := writeJSON(filepath.Join(sessionDir(root, id), "session.json"), rec); err != nil {
		return rec, err
	}
	return rec, nil
}

func Get(root, id string) (Record, error) {
	if !validID.MatchString(id) {
		return Record{}, fmt.Errorf("invalid investigation session id %q", id)
	}
	processMu.Lock()
	defer processMu.Unlock()
	return getUnlocked(root, id)
}

func getUnlocked(root, id string) (Record, error) {
	data, err := os.ReadFile(filepath.Join(sessionDir(root, id), "session.json"))
	if err != nil {
		return Record{}, fmt.Errorf("read diagnosis session %q: %w", id, err)
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return Record{}, fmt.Errorf("parse diagnosis session %q: %w", id, err)
	}
	file, err := os.Open(filepath.Join(sessionDir(root, id), "events.jsonl"))
	if os.IsNotExist(err) {
		return rec, nil
	}
	if err != nil {
		return Record{}, fmt.Errorf("open diagnosis session events: %w", err)
	}
	defer file.Close()
	rec.Events = nil
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), maxSummaryBytes+1024)
	for scanner.Scan() {
		if len(rec.Events) >= maxEvents {
			rec.Truncated = true
			break
		}
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return Record{}, fmt.Errorf("parse diagnosis session event: %w", err)
		}
		rec.Events = append(rec.Events, event)
	}
	if err := scanner.Err(); err != nil {
		return Record{}, fmt.Errorf("read diagnosis session events: %w", err)
	}
	return rec, nil
}

func sessionDir(root, id string) string {
	return filepath.Join(root, "diagnose-sessions", id)
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func writeJSONExclusive(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create diagnosis session metadata: %w", err)
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func truncate(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= maxSummaryBytes {
		return value
	}
	return value[:maxSummaryBytes] + "…"
}

func newID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate diagnosis session id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
