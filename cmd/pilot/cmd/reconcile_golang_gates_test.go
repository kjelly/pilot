package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/freeiparpc"
	"github.com/kjelly/pilot/internal/inventory"
)

// The Go preview refuses before it connects (spec §2.2): each gate here
// has a case that should trip it, driven through runReconcile like the
// cobra command, asserting the gate's own message or sentinel and that no
// tunnel was opened and no login sent. A refusal that "passed" only
// because another gate refused first would prove nothing, so every case
// names what must be in the error.

// golangServer is one freeipa-server host of golangServers' inventory.
type golangServer struct {
	name, addr string
	vars       map[string]any // more host variables, over the defaults
}

// golangServers replaces golangWorkspace's fake ansible-inventory and
// ansible with ones that know every given freeipa-server host and answer
// `ansible freeipa-server --list-hosts [--limit L]` the way ansible-core
// 2.19.2 does (captured with two hosts in one group): the hosts L names,
// comma-separated, or when it names none, two warnings, the error
// "Specified inventory, host pattern and/or --limit leaves us with no hosts
// to target." and exit 1.
func golangServers(t *testing.T, servers ...golangServer) {
	t.Helper()
	hostvars := map[string]any{}
	var names []string
	for _, s := range servers {
		names = append(names, s.name)
		vars := map[string]any{"freeipa_roster_file": ".vault/ipa-identity.yaml", "ansible_host": s.addr, "ansible_user": "root"}
		for k, v := range s.vars {
			vars[k] = v
		}
		hostvars[s.name] = vars
	}
	inv, err := json.Marshal(map[string]any{"_meta": map[string]any{"hostvars": hostvars}, "freeipa-server": map[string]any{"hosts": names}})
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("ansible-inventory", "#!/bin/sh\ncat <<'EOF'\n"+string(inv)+"\nEOF\n")
	write("ansible", `#!/bin/sh
limit=
while [ $# -gt 0 ]; do
  if [ "$1" = --limit ]; then limit=$2; shift; fi
  shift
done
n=0; out=
for h in `+strings.Join(names, " ")+`; do
  match=
  if [ -z "$limit" ]; then match=1; else
    IFS=,; for l in $limit; do [ "$l" = "$h" ] && match=1; done; unset IFS
  fi
  if [ -n "$match" ]; then n=$((n+1)); out="$out    $h
"; fi
done
if [ $n -eq 0 ] && [ -n "$limit" ]; then
  echo "[WARNING]: Could not match supplied host pattern, ignoring: $limit" >&2
  echo '[ERROR]: Specified inventory, host pattern and/or --limit leaves us with no hosts to target.' >&2
  exit 1
fi
printf '  hosts (%d):\n%s' $n "$out"
`)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// golangFakeVault puts an ansible-vault with the given shell body first on
// PATH. The preview reads an encrypted file through `ansible-vault view`.
func golangFakeVault(t *testing.T, body string) {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ansible-vault"), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// vaultCaptureStderr is a fake ansible-vault that fails with a real stderr
// capture of `ansible-vault view` (ansible-core 2.19.2, internal/inventory
// testdata) and exit status 1.
func vaultCaptureStderr(t *testing.T, name string) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "..", "internal", "inventory", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	return "cat '" + path + "' >&2\nexit 1"
}

// writeEncrypted replaces a workspace file with one that has an
// ansible-vault header; the fake ansible-vault stands in for decrypting it.
func writeEncrypted(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("$ANSIBLE_VAULT;1.1;AES256\n3132\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// assertNoLogin fails when the preview opened a tunnel connection or sent
// anything to the server: FQDN and CA are read over SSH, which is not a
// connection to FreeIPA.
func assertNoLogin(t *testing.T, f *fakeIPA) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dials != 0 || len(f.bodies) != 0 {
		t.Fatalf("the preview reached FreeIPA anyway: %d tunnel connections, requests %v", f.dials, f.methods)
	}
}

// Spec §2.2 step 2: exactly one freeipa-server host after --limit, else
// fail before any connection.
func TestReconcileGolangPreviewNeedsExactlyOneServer(t *testing.T) {
	roster := strings.Replace(captureRoster, "%s", "/bin/sh", 1)
	two := []golangServer{{name: "ipa-1", addr: "192.0.2.10"}, {name: "ipa-2", addr: "192.0.2.11"}}
	for _, tc := range []struct {
		name, limit, want, host string
	}{
		{name: "two servers", want: "有 2 台"},
		{name: "limit names both", limit: "ipa-1,ipa-2", want: "有 2 台"},
		{name: "limit leaves none", limit: "ipa-9", want: "有 0 台"},
		{name: "limit picks the second", limit: "ipa-2", host: "192.0.2.11"},
		{name: "limit picks the first", limit: "ipa-1", host: "192.0.2.10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeIPA(t, "p1-self")
			targets := withFakeDialer(t, f)
			golangWorkspace(t, roster, nil)
			golangServers(t, two...)
			var args []string
			if tc.limit != "" {
				args = []string{"--limit", tc.limit}
			}
			out, err := runGolangPreview(t, args...)
			if tc.want == "" {
				if err != nil || len(*targets) != 1 || (*targets)[0].Host != tc.host {
					t.Fatalf("err = %v, targets = %+v, want one tunnel to %s\n%s", err, *targets, tc.host, out)
				}
				if want := "目標：" + map[string]string{"192.0.2.10": "ipa-1", "192.0.2.11": "ipa-2"}[tc.host]; !strings.Contains(out, want) {
					t.Fatalf("the preview did not name its target (%q):\n%s", want, out)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "剛好一台 freeipa-server") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want the exactly-one refusal with %q\n%s", err, tc.want, out)
			}
			if !strings.Contains(err.Error(), fmt.Sprintf("--limit %q", tc.limit)) {
				t.Fatalf("the refusal does not show the --limit it saw: %v", err)
			}
			if len(*targets) != 0 {
				t.Fatalf("built a tunnel to %+v", *targets)
			}
			assertNoLogin(t, f)
		})
	}
}

// Spec §2.2 step 2: a hosts.yml that renders to another inventory fails,
// and the read-only preview leaves inventory.yml as it was.
func TestReconcileGolangPreviewRefusesAStaleInventory(t *testing.T) {
	const hosts = "hosts:\n  ipa-1:\n    ansible_host: \"192.0.2.10\"\n    freeipa_roster_file: .vault/ipa-identity.yaml\n    roles: [freeipa-server]\n"
	for _, current := range []bool{false, true} {
		t.Run(map[bool]string{false: "stale", true: "current"}[current], func(t *testing.T) {
			f := newFakeIPA(t, "p1-self")
			targets := withFakeDialer(t, f)
			dir := golangWorkspace(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1), nil)
			if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte(hosts), 0o600); err != nil {
				t.Fatal(err)
			}
			if current {
				hf, err := inventory.Parse([]byte(hosts))
				if err != nil {
					t.Fatal(err)
				}
				rendered, err := generateInventoryFromHosts(hf)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "inventory.yml"), []byte(rendered), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(filepath.Join(dir, "inventory.yml"))
			if err != nil {
				t.Fatal(err)
			}
			out, err := runGolangPreview(t)
			after, _ := os.ReadFile(filepath.Join(dir, "inventory.yml"))
			if string(before) != string(after) {
				t.Fatal("the preview rewrote inventory.yml")
			}
			if current {
				if err != nil || len(*targets) != 1 {
					t.Fatalf("a current inventory was refused: %v\n%s", err, out)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "與 hosts.yml 不一致") || !strings.Contains(err.Error(), "pilot inventory generate") {
				t.Fatalf("err = %v, want the stale-inventory refusal\n%s", err, out)
			}
			if len(*targets) != 0 {
				t.Fatalf("built a tunnel to %+v", *targets)
			}
			assertNoLogin(t, f)
		})
	}
}

// Spec §4: roster freeipa.server must equal the server's hostname -f,
// ignoring case; a mismatch fails before login.
func TestReconcileGolangPreviewChecksTheRosterServer(t *testing.T) {
	for _, tc := range []struct{ name, server, want string }{
		{name: "another server", server: "ipa-other.example.test", want: "roster freeipa.server 是 ipa-other.example.test，但 ipa-1 的 hostname -f 是 " + golangTestFQDN},
		{name: "case only", server: "IPA.Example.TEST"},
		{name: "exact", server: golangTestFQDN},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeIPA(t, "p1-self")
			targets := withFakeDialer(t, f)
			roster := strings.Replace(strings.Replace(captureRoster, "%s", "/bin/sh", 1),
				"  admin: {principal: p1-self}\n", "  server: "+tc.server+"\n  admin: {principal: p1-self}\n", 1)
			golangWorkspace(t, roster, nil)
			out, err := runGolangPreview(t)
			if tc.want == "" {
				if err != nil || len(*targets) != 1 {
					t.Fatalf("%s was refused: %v\n%s", tc.server, err, out)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q\n%s", err, tc.want, out)
			}
			assertNoLogin(t, f)
		})
	}
}

// The checks between loading the inventory and building the tunnel, each
// through runReconcile with a case that trips it.
func TestReconcileGolangPreviewEntryGates(t *testing.T) {
	noSecret := func(t *testing.T) string { return vaultCaptureStderr(t, "ansible-vault-view-no-secret.stderr") }
	wrongSecret := func(t *testing.T) string { return vaultCaptureStderr(t, "ansible-vault-view-wrong-secret.stderr") }
	for _, tc := range []struct {
		name string
		// setup edits the workspace golangWorkspace made; vault returns the
		// body of the fake ansible-vault, if the case reads one.
		setup  func(t *testing.T)
		vault  func(t *testing.T) string
		server map[string]any
		want   []string // substrings of the error
		is     error    // the error must wrap it
		isNot  []error  // and none of these
	}{
		{
			// The completeness gate is the only check that refuses an admin
			// password still reading CHANGE-ME: the preview would otherwise
			// log in with it.
			name: "completeness: the vault holds a CHANGE-ME admin password",
			setup: func(t *testing.T) {
				if err := os.WriteFile(filepath.Join(".vault", "main.yaml"), []byte("ipa_admin_password: CHANGE-ME-min-8-chars\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: []string{"inventory 完整性檢查沒過", "ipa_admin_password 是 CHANGE-ME"},
		},
		{
			name:  "vault vars file: no vault secret",
			setup: func(t *testing.T) { writeEncrypted(t, filepath.Join(".vault", "main.yaml")) },
			vault: noSecret,
			want:  []string{"讀取 vault vars 檔", "no vault secret is configured"},
			is:    inventory.ErrNoVaultSecret,
		},
		{
			name:  "vault vars file: the secret does not decrypt",
			setup: func(t *testing.T) { writeEncrypted(t, filepath.Join(".vault", "main.yaml")) },
			vault: wrongSecret,
			want:  []string{"讀取 vault vars 檔", "does not decrypt"},
			is:    inventory.ErrVaultDecryptFailed,
		},
		{
			name:  "vault vars file: ansible-vault fails another way",
			setup: func(t *testing.T) { writeEncrypted(t, filepath.Join(".vault", "main.yaml")) },
			vault: func(*testing.T) string { return "echo '[ERROR]: synthetic failure' >&2\nexit 2" },
			want:  []string{"讀取 vault vars 檔", "synthetic failure"},
			isNot: []error{inventory.ErrNoVaultSecret, inventory.ErrVaultDecryptFailed},
		},
		{
			name:  "roster: no vault secret",
			setup: func(t *testing.T) { writeEncrypted(t, filepath.Join(".vault", "ipa-identity.yaml")) },
			vault: noSecret,
			want:  []string{"讀取 roster", "no vault secret is configured"},
			is:    inventory.ErrNoVaultSecret,
		},
		{
			name:   "ssh target: a connection password",
			server: map[string]any{"ansible_ssh_pass": "x"},
			want:   []string{"ipa-1 設定了 ansible_ssh_pass", "--engine golang 不支援"},
		},
		{
			name:   "ssh target: not an ssh connection",
			server: map[string]any{"ansible_connection": "docker"},
			want:   []string{"ipa-1 的 ansible_connection 是 docker", "只支援 ssh"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeIPA(t, "p1-self")
			targets := withFakeDialer(t, f)
			var vault string
			if tc.vault != nil {
				vault = tc.vault(t) // resolves a path relative to the package directory
			}
			golangWorkspace(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1), nil)
			golangServers(t, golangServer{name: "ipa-1", addr: "192.0.2.10", vars: tc.server})
			if tc.setup != nil {
				tc.setup(t)
			}
			if vault != "" {
				golangFakeVault(t, vault)
			}
			out, err := runGolangPreview(t)
			if err == nil {
				t.Fatalf("the preview went through\n%s", out)
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("err = %v, want it to hold %q", err, want)
				}
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("err = %v, want it to wrap %v", err, tc.is)
			}
			for _, not := range tc.isNot {
				if errors.Is(err, not) {
					t.Fatalf("err = %v wraps %v", err, not)
				}
			}
			if len(*targets) != 0 {
				t.Fatalf("built a tunnel to %+v", *targets)
			}
			assertNoLogin(t, f)
		})
	}
}

// --timeout bounds the whole preview (spec §2.1), so also an
// ansible-vault that never ends: the read fails with the deadline, the
// fake ansible-vault is gone, and nothing is dialed.
func TestReconcileGolangPreviewVaultReadStopsAtTheTimeout(t *testing.T) {
	for _, tc := range []struct{ name, file, want string }{
		{name: "roster", file: "ipa-identity.yaml", want: "讀取 roster"},
		{name: "vault vars file", file: "main.yaml", want: "讀取 vault vars 檔"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeIPA(t, "p1-self")
			targets := withFakeDialer(t, f)
			golangWorkspace(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1), nil)
			writeEncrypted(t, filepath.Join(".vault", tc.file))
			started := filepath.Join(t.TempDir(), "started")
			// Long enough that a read nothing stops would finish after
			// the assertion on elapsed time below.
			golangFakeVault(t, "echo $$ > '"+started+"'\nexec sleep 20")
			begin := time.Now()
			out, err := runGolangPreview(t, "--timeout", "2s")
			elapsed := time.Since(begin)
			if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v after %s, want the deadline from %q\n%s", err, elapsed, tc.want, out)
			}
			if elapsed > 10*time.Second {
				t.Fatalf("the read took %s; --timeout 2s did not stop it", elapsed)
			}
			pid, err := os.ReadFile(started)
			if err != nil {
				t.Fatalf("ansible-vault never started, so the deadline hit something else: %v", err)
			}
			n, err := strconv.Atoi(strings.TrimSpace(string(pid)))
			if err != nil {
				t.Fatalf("pid file: %q: %v", pid, err)
			}
			if err := syscall.Kill(n, 0); !errors.Is(err, syscall.ESRCH) {
				t.Fatalf("ansible-vault (pid %d) outlived the preview: kill 0 = %v", n, err)
			}
			if len(*targets) != 0 {
				t.Fatalf("built a tunnel to %+v", *targets)
			}
			assertNoLogin(t, f)
		})
	}
}

// D10: the client the preview builds is read-only: a write is refused
// locally and never reaches the server.
func TestReconcileGolangPreviewBuildsAReadOnlyClient(t *testing.T) {
	f := newFakeIPA(t, "p1-self")
	withFakeDialer(t, f)
	golangWorkspace(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1), nil)
	prev := newGolangIPAClient
	t.Cleanup(func() { newGolangIPAClient = prev })
	var built []freeiparpc.Config
	newGolangIPAClient = func(cfg freeiparpc.Config) (*freeiparpc.Client, error) {
		c, err := prev(cfg)
		if err != nil {
			return nil, err
		}
		built = append(built, cfg)
		var refused *freeiparpc.ErrMethodNotAllowed
		if _, err := c.Call(context.Background(), freeiparpc.Command{Method: "user_mod", Args: []any{"p1-self"}}); !errors.As(err, &refused) || !refused.ReadOnly {
			t.Errorf("the preview's client sent or allowed a write: %v", err)
		}
		return c, nil
	}
	if out, err := runGolangPreview(t); err != nil {
		t.Fatalf("preview: %v\n%s", err, out)
	}
	if len(built) != 1 || !built[0].ReadOnly || built[0].FQDN != golangTestFQDN {
		t.Fatalf("built %d clients: %+v", len(built), built)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if slices.Contains(f.methods, "user_mod") {
		t.Fatalf("the write reached the server: %v", f.methods)
	}
}
