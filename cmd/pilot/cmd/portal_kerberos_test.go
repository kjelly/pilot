package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type portalCredentialCall struct {
	path  string
	args  []string
	input []byte
}

// TestNewPortalKerberosSessionWithPrefix proves the constructor Directory's
// own SSH hop reuses (docs/tmp/now/spec.md D5) actually threads its prefix
// through to the session, distinct from the interactive Portal's default.
func TestNewPortalKerberosSessionWithPrefix(t *testing.T) {
	s := newPortalKerberosSessionWithPrefix("pilot-directory-")
	if s.cacheDirPrefix != "pilot-directory-" {
		t.Fatalf("cacheDirPrefix = %q, want pilot-directory-", s.cacheDirPrefix)
	}
	if newPortalKerberosSession().cacheDirPrefix != "pilot-portal-" {
		t.Fatalf("newPortalKerberosSession()'s cacheDirPrefix changed from pilot-portal-")
	}
}

func TestPortalKerberosSessionReusesMatchingInheritedCache(t *testing.T) {
	var calls []portalCredentialCall
	s := &portalKerberosSession{
		inherited:   "KEYRING:persistent:1000:1000",
		runtimeBase: t.TempDir(),
		readPassword: func(string) ([]byte, error) {
			t.Fatal("password must not be requested for a valid inherited cache")
			return nil, nil
		},
		run: func(_ context.Context, input []byte, path string, args ...string) ([]byte, error) {
			calls = append(calls, portalCredentialCall{path: path, args: append([]string(nil), args...), input: append([]byte(nil), input...)})
			if path != klistBinaryPath {
				t.Fatalf("unexpected command %s %v", path, args)
			}
			if containsArg(args, "-s") {
				return nil, nil
			}
			return []byte("Ticket cache: KEYRING:persistent:1000:1000\nDefault principal: alice@IPA.PILOT.INTERNAL\n"), nil
		},
	}

	cache, err := s.Ensure(context.Background(), "alice")
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if cache != s.inherited {
		t.Fatalf("cache = %q, want inherited %q", cache, s.inherited)
	}
	s.Close()
	for _, call := range calls {
		if call.path == kdestroyBinaryPath {
			t.Fatal("Close must not destroy an inherited cache")
		}
	}
}

func TestPortalKerberosSessionAcquiresReusesAndDestroysOwnedCache(t *testing.T) {
	runtimeBase := t.TempDir()
	passwordReads := 0
	acquired := false
	var calls []portalCredentialCall
	s := &portalKerberosSession{
		runtimeBase:    runtimeBase,
		cacheDirPrefix: "pilot-portal-",
		readPassword: func(principal string) ([]byte, error) {
			passwordReads++
			if principal != "alice" {
				t.Fatalf("principal = %q, want alice", principal)
			}
			return []byte("portal-test-secret"), nil
		},
		run: func(_ context.Context, input []byte, path string, args ...string) ([]byte, error) {
			calls = append(calls, portalCredentialCall{path: path, args: append([]string(nil), args...), input: append([]byte(nil), input...)})
			switch path {
			case kinitBinaryPath:
				acquired = true
				return nil, nil
			case klistBinaryPath:
				if !acquired || !containsArg(args, "-c") {
					return nil, errors.New("no cache")
				}
				if containsArg(args, "-s") {
					return nil, nil
				}
				return []byte("Default principal: alice@IPA.PILOT.INTERNAL\n"), nil
			case kdestroyBinaryPath:
				return nil, nil
			default:
				t.Fatalf("unexpected command %s %v", path, args)
				return nil, nil
			}
		},
	}

	cache, err := s.Ensure(context.Background(), "alice")
	if err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	if !strings.HasPrefix(cache, "FILE:"+runtimeBase+string(os.PathSeparator)+"pilot-portal-") {
		t.Fatalf("cache = %q, want private runtime cache below %s", cache, runtimeBase)
	}
	if filepath.Base(strings.TrimPrefix(cache, "FILE:")) != "krb5cc" {
		t.Fatalf("cache path = %q, want krb5cc basename", cache)
	}
	if _, err := s.Ensure(context.Background(), "alice"); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if passwordReads != 1 {
		t.Fatalf("password reads = %d, want 1", passwordReads)
	}

	var kinitCalls []portalCredentialCall
	for _, call := range calls {
		if call.path == kinitBinaryPath {
			kinitCalls = append(kinitCalls, call)
		}
	}
	if len(kinitCalls) != 1 {
		t.Fatalf("kinit calls = %d, want 1", len(kinitCalls))
	}
	if want := []string{"-F", "-l", "1h", "-c", cache, "alice"}; !reflect.DeepEqual(kinitCalls[0].args, want) {
		t.Fatalf("kinit args = %v, want %v", kinitCalls[0].args, want)
	}
	if got := string(kinitCalls[0].input); got != "portal-test-secret\n" {
		t.Fatalf("kinit stdin did not contain exactly one password line")
	}

	ownedDir := s.ownedDir
	if info, err := os.Stat(ownedDir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("owned runtime dir mode = %v err=%v, want 0700", info, err)
	}
	s.Close()
	if _, err := os.Stat(ownedDir); !os.IsNotExist(err) {
		t.Fatalf("owned runtime dir still exists after Close: err=%v", err)
	}
	last := calls[len(calls)-1]
	if last.path != kdestroyBinaryPath || !reflect.DeepEqual(last.args, []string{"-c", cache}) {
		t.Fatalf("last command = %s %v, want kdestroy -c %s", last.path, last.args, cache)
	}
}

func TestPortalKerberosSessionReacquiresLostOwnedCache(t *testing.T) {
	passwordReads := 0
	cacheGeneration := 0
	cacheValid := false
	var destroyed []string
	s := &portalKerberosSession{
		runtimeBase: t.TempDir(),
		readPassword: func(string) ([]byte, error) {
			passwordReads++
			return []byte("portal-test-secret"), nil
		},
		run: func(_ context.Context, _ []byte, path string, args ...string) ([]byte, error) {
			switch path {
			case kinitBinaryPath:
				cacheGeneration++
				cacheValid = true
				return nil, nil
			case klistBinaryPath:
				if !containsArg(args, "-c") || !cacheValid {
					return nil, errors.New("cache unavailable")
				}
				if containsArg(args, "-s") {
					return nil, nil
				}
				return []byte("Default principal: alice@IPA.PILOT.INTERNAL\n"), nil
			case kdestroyBinaryPath:
				cacheValid = false
				destroyed = append(destroyed, args[len(args)-1])
				return nil, nil
			default:
				return nil, errors.New("unexpected command")
			}
		},
	}
	defer s.Close()

	first, err := s.Ensure(context.Background(), "alice")
	if err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	cacheValid = false // simulate an expired/deleted runtime cache
	second, err := s.Ensure(context.Background(), "alice")
	if err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if first == second {
		t.Fatalf("lost cache was reused: %q", first)
	}
	if passwordReads != 2 || cacheGeneration != 2 {
		t.Fatalf("passwordReads=%d cacheGeneration=%d, want 2/2", passwordReads, cacheGeneration)
	}
	if len(destroyed) != 1 || destroyed[0] != first {
		t.Fatalf("destroyed caches = %v, want [%s]", destroyed, first)
	}
}

func TestPortalKerberosSessionDoesNotReuseAnotherPrincipalsCache(t *testing.T) {
	prompts := 0
	acquired := false
	s := &portalKerberosSession{
		inherited:   "FILE:/tmp/other-cache",
		runtimeBase: t.TempDir(),
		readPassword: func(string) ([]byte, error) {
			prompts++
			return []byte("portal-test-secret"), nil
		},
		run: func(_ context.Context, _ []byte, path string, args ...string) ([]byte, error) {
			switch path {
			case kinitBinaryPath:
				acquired = true
				return nil, nil
			case klistBinaryPath:
				if containsArg(args, "-s") {
					return nil, nil
				}
				if containsArg(args, "FILE:/tmp/other-cache") {
					return []byte("Default principal: bob@IPA.PILOT.INTERNAL\n"), nil
				}
				if acquired {
					return []byte("Default principal: alice@IPA.PILOT.INTERNAL\n"), nil
				}
				return nil, errors.New("no cache")
			case kdestroyBinaryPath:
				return nil, nil
			default:
				return nil, errors.New("unexpected command")
			}
		},
	}
	defer s.Close()

	cache, err := s.Ensure(context.Background(), "alice")
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if cache == s.inherited {
		t.Fatal("must not reuse a cache belonging to bob")
	}
	if prompts != 1 {
		t.Fatalf("password prompts = %d, want 1", prompts)
	}
}

func TestPortalKerberosSessionRejectsUsernameInjection(t *testing.T) {
	s := &portalKerberosSession{
		readPassword: func(string) ([]byte, error) {
			t.Fatal("password must not be requested for an invalid username")
			return nil, nil
		},
		run: func(context.Context, []byte, string, ...string) ([]byte, error) {
			t.Fatal("no command may run for an invalid username")
			return nil, nil
		},
	}
	if _, err := s.Ensure(context.Background(), "alice@OTHER.REALM"); err == nil {
		t.Fatal("expected username injection to be rejected")
	}
}

func TestKerberosCachePrincipal(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
		want string
	}{
		{name: "user", out: "Default principal: alice@IPA.PILOT.INTERNAL\n", want: "alice"},
		{name: "instance rejected", out: "Default principal: alice/admin@IPA.PILOT.INTERNAL\n", want: ""},
		{name: "missing", out: "Ticket cache: FILE:/tmp/x\n", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := kerberosCachePrincipal([]byte(tc.out)); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}
