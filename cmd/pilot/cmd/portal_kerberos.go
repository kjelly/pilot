package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

const (
	kinitBinaryPath    = "/usr/bin/kinit"
	klistBinaryPath    = "/usr/bin/klist"
	kdestroyBinaryPath = "/usr/bin/kdestroy"
	portalTicketLife   = "1h"
)

var portalKerberosUsername = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// portalCredentialSession supplies the user credential used by the
// controlled Portal -> target SSH client. Implementations may reuse a valid
// credential delegated into the SSH session, but must never destroy a cache
// they did not create themselves.
type portalCredentialSession interface {
	Ensure(context.Context, string) (string, error)
	Close()
}

type portalCredentialCommandRunner func(context.Context, []byte, string, ...string) ([]byte, error)
type portalPasswordReader func(string) ([]byte, error)

// portalKerberosSession owns at most one session-scoped Kerberos cache. It
// intentionally has no persistent state: a missing/expired cache is acquired
// again from the KDC, and Close destroys only the cache this instance made.
type portalKerberosSession struct {
	run          portalCredentialCommandRunner
	readPassword portalPasswordReader
	runtimeBase  string
	inherited    string

	// cacheDirPrefix names the per-session temp directory this instance's
	// Ensure creates (os.MkdirTemp's pattern arg) — component-specific
	// (e.g. "pilot-portal-" vs "pilot-directory-") purely so an operator
	// inspecting /run/user/<uid> can tell which caller owns a given
	// leftover directory; it has no effect on behavior or security.
	cacheDirPrefix string

	ownedCache string
	ownedDir   string
}

// newPortalKerberosSession builds a session for the interactive Portal
// Connect flow (spec.md §32.1).
func newPortalKerberosSession() *portalKerberosSession {
	return newPortalKerberosSessionWithPrefix("pilot-portal-")
}

// newPortalKerberosSessionWithPrefix is newPortalKerberosSession, generalized
// for any caller that needs this same self-managed session-scoped ticket
// acquisition (docs/tmp/now/spec.md D5: pilot-access-directory's own SSH hop
// to a Gateway reuses this exact mechanism rather than relying on inbound
// GSSAPIDelegateCredentials — the same problem this file's original commit
// found unreliable for the sibling Gateway->target hop).
func newPortalKerberosSessionWithPrefix(cacheDirPrefix string) *portalKerberosSession {
	return &portalKerberosSession{
		run:            runPortalCredentialCommand,
		readPassword:   readPortalKerberosPassword,
		runtimeBase:    portalKerberosRuntimeBase(os.Getuid()),
		inherited:      os.Getenv("KRB5CCNAME"),
		cacheDirPrefix: cacheDirPrefix,
	}
}

func runPortalCredentialCommand(ctx context.Context, input []byte, path string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = replaceProcessEnv(os.Environ(), "LC_ALL", "C")
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	return cmd.CombinedOutput()
}

func readPortalKerberosPassword(principal string) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("Kerberos password requires an interactive terminal")
	}
	fmt.Fprintf(os.Stderr, "Kerberos password for %s: ", principal)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return password, err
}

// portalKerberosRuntimeBase prefers pam_systemd's per-user tmpfs. MkdirTemp
// still creates a private 0700 directory when /run/user/<uid> is unavailable
// (for example in a stripped-down test VM) and has to fall back to /tmp.
func portalKerberosRuntimeBase(uid int) string {
	path := filepath.Join("/run/user", strconv.Itoa(uid))
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return path
	}
	return os.TempDir()
}

func (s *portalKerberosSession) Ensure(ctx context.Context, username string) (string, error) {
	if !portalKerberosUsername.MatchString(username) {
		return "", fmt.Errorf("refusing invalid Kerberos username %q", username)
	}

	if s.ownedCache != "" {
		if s.cacheValid(ctx, s.ownedCache, username) {
			return s.ownedCache, nil
		}
		s.destroyOwnedCache()
	}
	if s.cacheValid(ctx, s.inherited, username) {
		return s.inherited, nil
	}

	password, err := s.readPassword(username)
	if err != nil {
		return "", err
	}
	defer wipeBytes(password)
	if len(password) == 0 {
		return "", errors.New("Kerberos password cannot be empty")
	}

	dir, err := os.MkdirTemp(s.runtimeBase, s.cacheDirPrefix)
	if err != nil {
		return "", fmt.Errorf("create session credential directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("secure session credential directory: %w", err)
	}
	cache := "FILE:" + filepath.Join(dir, "krb5cc")
	input := make([]byte, len(password)+1)
	copy(input, password)
	input[len(input)-1] = '\n'
	defer wipeBytes(input)

	if _, err := s.run(ctx, input, kinitBinaryPath, "-F", "-l", portalTicketLife, "-c", cache, username); err != nil {
		_ = os.RemoveAll(dir)
		return "", errors.New("Kerberos authentication failed; verify the password or update an expired password with kinit/kpasswd")
	}
	s.ownedCache = cache
	s.ownedDir = dir
	if !s.cacheValid(ctx, cache, username) {
		s.destroyOwnedCache()
		return "", errors.New("Kerberos authentication did not produce a valid ticket for the Portal user")
	}
	return cache, nil
}

func (s *portalKerberosSession) cacheValid(ctx context.Context, cache, username string) bool {
	silentArgs := []string{"-s"}
	showArgs := []string{}
	if cache != "" {
		silentArgs = append(silentArgs, "-c", cache)
		showArgs = append(showArgs, "-c", cache)
	}
	if _, err := s.run(ctx, nil, klistBinaryPath, silentArgs...); err != nil {
		return false
	}
	out, err := s.run(ctx, nil, klistBinaryPath, showArgs...)
	if err != nil {
		return false
	}
	return kerberosCachePrincipal(out) == username
}

func kerberosCachePrincipal(output []byte) string {
	for _, line := range strings.Split(string(output), "\n") {
		const prefix = "Default principal:"
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		principal := strings.TrimSpace(strings.TrimPrefix(line, prefix))
		primary := strings.SplitN(principal, "@", 2)[0]
		if strings.Contains(primary, "/") {
			return ""
		}
		return primary
	}
	return ""
}

func (s *portalKerberosSession) Close() {
	s.destroyOwnedCache()
}

func (s *portalKerberosSession) destroyOwnedCache() {
	if s.ownedCache == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = s.run(ctx, nil, kdestroyBinaryPath, "-c", s.ownedCache)
	if s.ownedDir != "" {
		_ = os.RemoveAll(s.ownedDir)
	}
	s.ownedCache = ""
	s.ownedDir = ""
}

func replaceProcessEnv(env []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	for _, entry := range env {
		if !strings.HasPrefix(entry, prefix) {
			out = append(out, entry)
		}
	}
	return append(out, prefix+value)
}

func wipeBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
