package mcpremote

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/kjelly/pilot/internal/mcpwire"
)

// Retention of edit sessions (spec §7.4).
const (
	gcBudget          = 2 * time.Second
	orphanGrace       = 10 * time.Minute
	endedRetention    = 7 * 24 * time.Hour
	absoluteRetention = 30 * 24 * time.Hour
)

// CollectEditSessions reclaims edit sessions nobody is using: a directory
// without session.json past the grace period (the session died before
// writing it), a session stuck in serving (its container was killed), and
// sessions past retention. Only directories whose lock is free are
// touched, and the lock is held while they are changed. Failures are
// logged and never fail the request (AGENTS.md §5.14 item 5).
func CollectEditSessions(cfg *Config) {
	root := cfg.sessionsRoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("mcp remote: list edit sessions", "err", err)
		}
		return
	}
	deadline := time.Now().Add(gcBudget)
	now := cfg.now()
	for _, e := range entries {
		if time.Now().After(deadline) {
			return
		}
		if !e.IsDir() || !mcpwire.ValidSessionID(e.Name()) {
			continue
		}
		dir := filepath.Join(root, e.Name())
		if err := collectOne(cfg, dir, now); err != nil {
			slog.Warn("mcp remote: collect edit session", "session", e.Name(), "err", err)
		}
	}
}

func collectOne(cfg *Config, dir string, now time.Time) error {
	// Read the age before locking: creating a missing .lock would itself
	// touch the directory's mtime.
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	// A young directory without session.json may be a session that has
	// just been created and not locked yet; taking its lock first would
	// make that session fail. Leave it alone without touching the lock.
	if _, err := os.Lstat(filepath.Join(dir, "session.json")); os.IsNotExist(err) && now.Sub(info.ModTime()) <= orphanGrace {
		return nil
	}
	lock, err := tryLock(filepath.Join(dir, ".lock"))
	if err != nil || lock == nil {
		return err // in use, or unreadable
	}
	defer lock.Close()
	state, ok, err := loadSession(dir)
	if err != nil {
		return err
	}
	if !ok {
		if now.Sub(info.ModTime()) > orphanGrace {
			return os.RemoveAll(dir)
		}
		return nil
	}
	switch {
	case now.Sub(state.CreatedAt) > absoluteRetention:
		return os.RemoveAll(dir)
	case state.State == stateServing:
		return endEditSession(cfg, dir, state)
	case state.State == stateEnded && now.Sub(state.EndedAt) > endedRetention:
		return os.RemoveAll(dir)
	}
	return nil
}
