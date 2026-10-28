package inventory

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

// lockTestRoster is a schema-v3 roster on which every roster writer below
// has something to change and every validating writer accepts the result.
const lockTestRoster = `schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin:
    principal: admin
    password: "Old-pass_1"
users:
  - name: alice
    ssh_keys: {authoritative: true, values: []}
  - name: vendor01
    ssh_keys: {authoritative: true, values: []}
  - name: dave
    ssh_keys: {authoritative: true, values: []}
groups:
  - name: team-sre
    category: team
    membership: {users: [alice], groups: []}
  - name: team-empty
    category: team
    membership: {users: [], groups: []}
  - name: role-privileged
    category: role
    membership: {users: [alice], groups: []}
hosts:
  - name: db-special.ipa.pilot.internal
    ip_address: 10.0.0.5
hostgroups:
  - name: production-db
    membership: {authoritative: true, hosts: [db-special.ipa.pilot.internal], hostgroups: []}
hbac:
  rules:
    - name: allow-sre
      subjects: {users: [], groups: [team-sre]}
      targets: {hosts: [], hostgroups: [production-db]}
      services: [sshd]
sudo:
  rules: []
grants:
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2099-08-31T18:00:00Z"}
    justification: {reason: "Project X maintenance"}
    review: {interval: 30d, last_reviewed_at: "2026-08-01T10:00:00Z", reviewed_by: alice}
credential_policies:
  - name: privileged-ssh
    match: {users: [], groups: [role-privileged]}
    review: {interval: 180d}
password_policies:
  - name: pw-sre
    group: team-sre
    priority: 1
nfs:
  servers:
    - host: nfs1.ipa.pilot.internal
      state: present
      service_principal: {ensure: true, principal: nfs/nfs1.ipa.pilot.internal, keytab: /etc/krb5.keytab}
      shares: []
`

// rosterWriterCase calls one roster writer on path. body is the roster it
// starts from; create marks a create-only writer, whose roster must not
// exist yet; encrypt has the roster ansible-vault encrypted first.
type rosterWriterCase struct {
	body    string
	create  bool
	encrypt bool
	call    func(t *testing.T, path string) error
}

func rosterWriterCases() map[string]rosterWriterCase {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	entry := func(fields ...string) map[string]any {
		out := map[string]any{}
		for i := 0; i+1 < len(fields); i += 2 {
			out[fields[i]] = fields[i+1]
		}
		return out
	}
	plain := func(call func(path string) error) rosterWriterCase {
		return rosterWriterCase{body: lockTestRoster, call: func(_ *testing.T, path string) error { return call(path) }}
	}
	return map[string]rosterWriterCase{
		"AppendMissingNFSServerStub": plain(func(path string) error {
			_, err := AppendMissingNFSServerStub(path, "nfs2", "ipa.pilot.internal")
			return err
		}),
		"AppendRosterGrant": plain(func(path string) error { return AppendRosterGrant(path, entry("name", "g2")) }),
		"SetRosterGrant": plain(func(path string) error {
			return SetRosterGrant(path, "vendor-project-x", entry("name", "vendor-project-x", "state", "absent"))
		}),
		"SetRosterHBACDisableAllowAll": plain(func(path string) error { return SetRosterHBACDisableAllowAll(path, true) }),
		"AppendRosterHostgroup":        plain(func(path string) error { return AppendRosterHostgroup(path, "web") }),
		"AppendRosterNFSClient":        plain(func(path string) error { return AppendRosterNFSClient(path, entry("hostgroup", "web")) }),
		"AppendRosterHBACRule":         plain(func(path string) error { return AppendRosterHBACRule(path, entry("name", "allow-more")) }),
		"SetRosterHostgroup": plain(func(path string) error {
			return SetRosterHostgroup(path, "production-db", entry("name", "production-db"))
		}),
		"SetRosterHBACRule": plain(func(path string) error { return SetRosterHBACRule(path, "allow-sre", entry("name", "allow-sre")) }),
		"AppendRosterUser":  plain(func(path string) error { return AppendRosterUser(path, "erin") }),
		"AppendRosterGroup": plain(func(path string) error { return AppendRosterGroup(path, "team-new", "team") }),
		"AppendRosterHost":  plain(func(path string) error { return AppendRosterHost(path, "web1.ipa.pilot.internal", "10.0.0.9") }),
		"SetRosterUser": plain(func(path string) error {
			return SetRosterUser(path, "alice", entry("name", "alice", "state", "absent"))
		}),
		"SetRosterGroup": plain(func(path string) error {
			return SetRosterGroup(path, "team-sre", entry("name", "team-sre", "category", "team"))
		}),
		"RemoveRosterHostReferences": plain(func(path string) error { return RemoveRosterHostReferences(path, "db-special.ipa.pilot.internal") }),
		"SetRosterHostAbsent":        plain(func(path string) error { return SetRosterHostAbsent(path, "db-special.ipa.pilot.internal") }),
		"AppendRosterPasswordPolicy": plain(func(path string) error { return AppendRosterPasswordPolicy(path, "pw-new") }),
		"SetRosterPasswordPolicy": plain(func(path string) error {
			return SetRosterPasswordPolicy(path, "pw-sre", entry("name", "pw-sre", "state", "absent"))
		}),
		"AppendRosterCredentialPolicy": plain(func(path string) error { return AppendRosterCredentialPolicy(path, "cp-new") }),
		"SetRosterCredentialPolicy": plain(func(path string) error {
			return SetRosterCredentialPolicy(path, "privileged-ssh", entry("name", "privileged-ssh", "state", "absent"))
		}),
		"SetRosterPrivilegedIdentity":  plain(func(path string) error { return SetRosterPrivilegedIdentity(path, entry("password_policy", "pw-sre")) }),
		"SetRosterNFSServerAbsent":     plain(func(path string) error { return SetRosterNFSServerAbsent(path, "nfs1.ipa.pilot.internal") }),
		"RemoveRosterUser":             plain(func(path string) error { return RemoveRosterUser(path, "dave", RemoveRosterUserOptions{}) }),
		"RemoveRosterGroup":            plain(func(path string) error { return RemoveRosterGroup(path, "team-empty", RemoveRosterGroupOptions{}) }),
		"AppendRosterSudoCommandGroup": plain(func(path string) error { return AppendRosterSudoCommandGroup(path, entry("name", "cg-new")) }),
		"SetRosterSudoCommandGroup": {body: strings.Replace(lockTestRoster, "sudo:\n", "sudo:\n  command_groups:\n    - name: cg\n", 1), call: func(_ *testing.T, path string) error {
			return SetRosterSudoCommandGroup(path, "cg", entry("name", "cg", "description", "changed"))
		}},
		"AppendRosterSudoRule": plain(func(path string) error { return AppendRosterSudoRule(path, entry("name", "rule-new")) }),
		"SetRosterSudoRule": {body: strings.Replace(lockTestRoster, "sudo:\n  rules: []\n", "sudo:\n  rules:\n    - name: rule-a\n", 1), call: func(_ *testing.T, path string) error {
			return SetRosterSudoRule(path, "rule-a", entry("name", "rule-a", "description", "changed"))
		}},
		"SyncRosterAdminPassword": plain(func(path string) error {
			_, err := SyncRosterAdminPassword(path, "Old-pass_1", "New-pass_2")
			return err
		}),
		"MarkGrantReviewedFile": plain(func(path string) error {
			return MarkGrantReviewedFile(path, "", "vendor-project-x", "alice", now)
		}),
		"MarkCredentialPolicyReviewedFile": plain(func(path string) error {
			return MarkCredentialPolicyReviewedFile(path, "", "privileged-ssh", "alice", now)
		}),
		"AutoFillFreeIPAClientRosterHosts": {body: lockTestRoster, call: func(t *testing.T, path string) error {
			dir := t.TempDir()
			hosts := "hosts:\n  web2.ipa.pilot.internal:\n    ansible_host: 10.0.0.12\n    roles: [freeipa-client]\n"
			if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte(hosts), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := AutoFillFreeIPAClientRosterHosts(dir, path)
			return err
		}},
		"MigrateRosterFile": {body: minimalValidRoster, call: func(_ *testing.T, path string) error {
			_, err := MigrateRosterFile(path, RosterMigrationOptions{})
			return err
		}},
		"EnsureRosterCurrent": {body: minimalValidRoster, call: func(_ *testing.T, path string) error {
			_, err := EnsureRosterCurrent(path, RosterMigrationOptions{})
			return err
		}},
		"MutateEncryptedRosterFile": {body: removeFixture, encrypt: true, call: func(t *testing.T, path string) error {
			return MutateEncryptedRosterFile(path, lockTestVaultPasswordFile(t), func(plaintextPath string) error {
				return RemoveRosterUser(plaintextPath, "dave", RemoveRosterUserOptions{})
			})
		}},
		"RestoreRosterFile": plain(func(path string) error {
			return RestoreRosterFile(path, []byte(lockTestRoster), []byte(lockTestRoster+"# restored\n"))
		}),
		"WriteMinimalNFSServerRoster": {create: true, call: func(_ *testing.T, path string) error {
			return WriteMinimalNFSServerRoster(path, "nfs1", "ipa.pilot.internal", "admin", "Admin-pass_1")
		}},
		"WriteMinimalRosterSkeleton": {create: true, call: func(_ *testing.T, path string) error {
			return WriteMinimalRosterSkeleton(path, "admin", "Admin-pass_1")
		}},
	}
}

// lockTestVaultPasswordFile writes the test vault password outside the
// roster's directory, so it never shows up among the files compared.
func lockTestVaultPasswordFile(t *testing.T) string {
	t.Helper()
	return writeVaultPasswordFile(t, filepath.Join(t.TempDir(), "vault-pass"), "s3cret-pw")
}

// lockTestLayout builds one writer's roster: the real file, an absolute
// symlink to it in another directory, and the spelling of each. A
// create-only writer gets no file; its link spelling goes through a
// symlinked directory instead, since a link to a missing file is dangling.
type lockTestLayout struct {
	target, link string
	before       []byte
	exists       bool
}

func newLockTestLayout(t *testing.T, tc rosterWriterCase) lockTestLayout {
	t.Helper()
	realDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	linkDir := t.TempDir()
	l := lockTestLayout{target: filepath.Join(realDir, "roster.yaml")}
	if tc.create {
		if err := os.Symlink(realDir, filepath.Join(linkDir, "dir")); err != nil {
			t.Fatal(err)
		}
		l.link = filepath.Join(linkDir, "dir", "roster.yaml")
		return l
	}
	if err := os.WriteFile(l.target, []byte(tc.body), 0o600); err != nil {
		t.Fatal(err)
	}
	if tc.encrypt {
		requireAnsibleVault(t)
		encryptFileForTest(t, l.target, lockTestVaultPasswordFile(t))
	}
	l.link = filepath.Join(linkDir, "roster.yaml")
	if err := os.Symlink(l.target, l.link); err != nil {
		t.Fatal(err)
	}
	l.before, l.exists = mustRead(t, l.target), true
	return l
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// assertUntouched checks the roster still holds its bytes (or still does
// not exist) and the link is still a link to it.
func (l lockTestLayout) assertUntouched(t *testing.T) {
	t.Helper()
	if !l.exists {
		if _, err := os.Lstat(l.target); !os.IsNotExist(err) {
			t.Fatalf("create-only roster was created under the lock (lstat err=%v)", err)
		}
		return
	}
	if after := mustRead(t, l.target); !bytes.Equal(after, l.before) {
		t.Fatalf("roster changed under the lock:\n%s", after)
	}
	l.assertStillALink(t)
}

func (l lockTestLayout) assertStillALink(t *testing.T) {
	t.Helper()
	if !l.exists {
		return
	}
	info, err := os.Lstat(l.link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s is no longer a symlink (mode %v, err %v)", l.link, info.Mode(), err)
	}
	if dest, err := os.Readlink(l.link); err != nil || dest != l.target {
		t.Fatalf("%s now points at %q (err %v), want %s", l.link, dest, err, l.target)
	}
}

// holdRawLocks holds the given roster sidecar locks on path itself, as
// another pilot process working on that spelling would — including an
// older binary that took only its own family's lock.
func holdRawLocks(t *testing.T, path string, suffixes ...string) {
	t.Helper()
	for _, suffix := range suffixes {
		lock, err := acquireMutationLock(path + suffix)
		if err != nil {
			t.Fatalf("hold %s: %v", path+suffix, err)
		}
		t.Cleanup(func() { lock.release() }) //nolint:errcheck
	}
}

// Every roster writer refuses a roster another roster writer holds on its
// real path — whichever lock family that one took, and whether this call
// spells the roster directly or through a symlink — and leaves the file
// and the link as they were. Unlocked, each one does change the roster
// and keeps the link, so the refusals are not some other failure (PR #148
// review: the admin password sync rewrote a roster through its link while
// `pilot roster remove-*` held it).
func TestRosterWritersRefuseALockedRoster(t *testing.T) {
	shortLockContentionWait(t)
	cases := rosterWriterCases()
	assertCoversEveryRosterWriter(t, cases)
	holders := map[string][]string{
		"both locks":   {".pilot-migrate.lock", ".pilot-remove.lock"},
		"migrate lock": {".pilot-migrate.lock"},
		"remove lock":  {".pilot-remove.lock"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Run("unlocked", func(t *testing.T) {
				l := newLockTestLayout(t, tc)
				var inode uint64
				if info, err := os.Stat(l.target); err == nil {
					inode = info.Sys().(*syscall.Stat_t).Ino
				}
				if err := tc.call(t, l.link); err != nil {
					t.Fatalf("unlocked call through the link: %v", err)
				}
				after, err := os.ReadFile(l.target)
				if err != nil || bytes.Equal(after, l.before) {
					t.Fatalf("unlocked call through the link did not write the roster (err %v)", err)
				}
				l.assertStillALink(t)
				// A roster with one name whose owner this process can keep is
				// replaced, not rewritten in place: a reader without the lock
				// never sees a truncated roster.
				if info, err := os.Stat(l.target); err == nil && l.exists && info.Sys().(*syscall.Stat_t).Ino == inode {
					t.Errorf("a roster with one name and this process's owner was rewritten in place (same inode), not replaced")
				}
				assertNoRosterTemps(t, l.target)
			})
			t.Run("write policy", func(t *testing.T) {
				assertRosterWritePolicy(t, tc)
			})
			for holder, suffixes := range holders {
				for spelling, pick := range map[string]func(lockTestLayout) string{
					"via link": func(l lockTestLayout) string { return l.link },
					"direct":   func(l lockTestLayout) string { return l.target },
				} {
					t.Run(holder+"/"+spelling, func(t *testing.T) {
						l := newLockTestLayout(t, tc)
						holdRawLocks(t, l.target, suffixes...)
						if err := tc.call(t, pick(l)); !errors.Is(err, ErrMutationLocked) {
							t.Fatalf("error = %v, want ErrMutationLocked", err)
						}
						l.assertUntouched(t)
					})
				}
			}
		})
	}
}

// assertNoRosterTemps fails when a temp file is left beside target.
func assertNoRosterTemps(t *testing.T, target string) {
	t.Helper()
	entries, _ := os.ReadDir(filepath.Dir(target))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "."+filepath.Base(target)+rosterTempInfix) {
			t.Errorf("temp file %s left beside the roster", e.Name())
		}
	}
}

// assertRosterWritePolicy holds one writer to writeLockedRoster's policy
// (PR #148 re-review, round 4): a roster this user may not write is
// refused, as an in-place write always refused it; a roster with another
// hard link is written in place, so every name sees the new content; a
// temp file a killed pilot left is swept once stale, and one still fresh is
// kept; run as root, the owner and group survive, and a new roster gets
// its directory's owner.
func assertRosterWritePolicy(t *testing.T, tc rosterWriterCase) {
	if !tc.create {
		t.Run("read-only roster", func(t *testing.T) {
			if os.Geteuid() == 0 {
				t.Skip("root writes a 0400 roster, as an in-place write always did")
			}
			l := newLockTestLayout(t, tc)
			if err := os.Chmod(l.target, 0o400); err != nil {
				t.Fatal(err)
			}
			if err := tc.call(t, l.link); err == nil {
				t.Fatal("a 0400 roster was written")
			}
			l.assertUntouched(t)
		})
		t.Run("hard link", func(t *testing.T) {
			l := newLockTestLayout(t, tc)
			other := filepath.Join(t.TempDir(), "other-name.yaml")
			if err := os.Link(l.target, other); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(l.target)
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.call(t, l.link); err != nil {
				t.Fatal(err)
			}
			after, err := os.Stat(l.target)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(before, after) || !bytes.Equal(mustRead(t, other), mustRead(t, l.target)) || bytes.Equal(mustRead(t, l.target), l.before) {
				t.Fatal("a roster with another hard link was replaced instead of written in place")
			}
			assertNoRosterTemps(t, l.target)
		})
	}
	t.Run("stale temp files", func(t *testing.T) {
		l := newLockTestLayout(t, tc)
		dir, base := filepath.Dir(l.target), filepath.Base(l.target)
		stale := []string{filepath.Join(dir, "."+base+rosterTempInfix+"stale"), filepath.Join(dir, "."+base+".migrate-stale")}
		fresh := filepath.Join(dir, "."+base+rosterTempInfix+"fresh")
		old := time.Now().Add(-10 * time.Minute)
		for _, path := range append(stale, fresh) {
			if err := os.WriteFile(path, []byte("plaintext left by a killed pilot"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		for _, path := range stale {
			if err := os.Chtimes(path, old, old); err != nil {
				t.Fatal(err)
			}
		}
		if err := tc.call(t, l.link); err != nil {
			t.Fatal(err)
		}
		for _, path := range stale {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Errorf("stale temp %s not swept (lstat err=%v)", filepath.Base(path), err)
			}
		}
		if _, err := os.Lstat(fresh); err != nil {
			t.Errorf("a fresh temp file was swept: %v", err)
		}
	})
	t.Run("owner kept as root", func(t *testing.T) {
		requireRoot(t)
		const uid, gid = 12345, 12346
		l := newLockTestLayout(t, tc)
		owned := l.target
		if tc.create {
			owned = filepath.Dir(l.target)
		}
		if err := os.Chown(owned, uid, gid); err != nil {
			t.Fatal(err)
		}
		if err := tc.call(t, l.link); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(l.target)
		if err != nil {
			t.Fatal(err)
		}
		if st := info.Sys().(*syscall.Stat_t); st.Uid != uid || st.Gid != gid {
			t.Fatalf("roster owned by %d:%d after the write, want %d:%d", st.Uid, st.Gid, uid, gid)
		}
	})
}

// shortLockContentionWait makes a held lock refuse a writer after 1ms for
// t, for tests about which writers refuse, not how long they wait
// (TestRosterLockContentionIsBriefAndBounded keeps the real wait). This
// package's tests do not run in parallel.
func shortLockContentionWait(t *testing.T) {
	t.Helper()
	old := lockContentionWait
	lockContentionWait = time.Millisecond
	t.Cleanup(func() { lockContentionWait = old })
}

// requireRoot skips t unless it runs as root, and fails it instead when
// PILOT_REQUIRE_ROOT_TESTS=1 (`make root-test`), so a run meant to
// exercise these cannot pass by skipping them.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		return
	}
	if os.Getenv("PILOT_REQUIRE_ROOT_TESTS") == "1" {
		t.Fatal("PILOT_REQUIRE_ROOT_TESTS=1 but this test is not running as root")
	}
	t.Skip("needs root")
}

// A non-root writer cannot give a replacement file another user's
// ownership; then the roster is written in place, so it keeps its owner
// rather than becoming the writer's (PR #148 re-review, round 4).
func TestWriteLockedRosterWritesInPlaceWhenTheOwnerCannotBeKept(t *testing.T) {
	path := writeLockTestRoster(t)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	fchownRosterTemp = func(*os.File, int, int) error { return syscall.EPERM }
	t.Cleanup(func() { fchownRosterTemp = func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) } })
	if err := AppendRosterUser(path, "erin"); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || !bytes.Contains(mustRead(t, path), []byte("erin")) {
		t.Fatal("the roster was replaced although its owner could not be kept")
	}
	assertNoRosterTemps(t, path)
}

// Run as root, a migration's backup belongs to the roster's owner, like the
// roster it copies (PR #148 re-review, round 4).
func TestMigrationBackupKeepsTheRosterOwner(t *testing.T) {
	requireRoot(t)
	const uid, gid = 12345, 12346
	path := writeRoster(t, minimalValidRoster)
	if err := os.Chown(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	result, err := MigrateRosterFile(path, RosterMigrationOptions{})
	if err != nil || !result.Changed {
		t.Fatalf("MigrateRosterFile() = %+v, %v", result, err)
	}
	for _, file := range []string{path, result.BackupPath} {
		info, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		if st := info.Sys().(*syscall.Stat_t); st.Uid != uid || st.Gid != gid {
			t.Errorf("%s owned by %d:%d, want %d:%d", filepath.Base(file), st.Uid, st.Gid, uid, gid)
		}
	}
}

// assertCoversEveryRosterWriter fails when an exported function of this
// package writes a roster (reaches a write TestRegression_RosterWriters
// LockCanonicalTarget audits) but has no case above.
func assertCoversEveryRosterWriter(t *testing.T, cases map[string]rosterWriterCase) {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	funcs := map[string]*ast.FuncDecl{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				funcs[funcName(fn)] = fn
			}
		}
	}
	writes := map[string]bool{}
	for name, fn := range funcs {
		if _, exempt := rosterWriterExemptions[name]; !exempt && len(rosterWritesIn(fn)) > 0 {
			writes[name] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for name, fn := range funcs {
			if writes[name] {
				continue
			}
			for _, callee := range calleesOf(fn) {
				if inSet(writes, callee) {
					writes[name], changed = true, true
					break
				}
			}
		}
	}
	var missing []string
	for name := range writes {
		if _, ok := cases[name]; !ok && ast.IsExported(name) && !strings.Contains(name, ".") {
			missing = append(missing, name)
		}
	}
	for name := range cases {
		if !writes[name] {
			t.Errorf("case %s does not name an exported roster writer", name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("roster writers without a lock case: %v", missing)
	}
}

// rosterSpellings returns the ways of naming dir/real.yaml that lockRosterFile
// must treat as one file.
func rosterSpellings(t *testing.T, dir, target string) map[string]string {
	t.Helper()
	other := t.TempDir()
	symlink := func(dest, link string) string {
		if err := os.Symlink(dest, link); err != nil {
			t.Fatal(err)
		}
		return link
	}
	chainMid := symlink("real.yaml", filepath.Join(dir, "mid.yaml"))
	return map[string]string{
		"absolute link": symlink(target, filepath.Join(other, "abs.yaml")),
		"relative link": symlink("real.yaml", filepath.Join(dir, "rel.yaml")),
		"chained link":  symlink(chainMid, filepath.Join(other, "chain.yaml")),
		"relative path": func() string {
			cwd, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			rel, err := filepath.Rel(cwd, target)
			if err != nil {
				t.Fatal(err)
			}
			return rel
		}(),
		"linked directory": filepath.Join(symlink(dir, filepath.Join(other, "dir")), "real.yaml"),
	}
}

// One roster has one lock, whichever spelling took it and whichever asks:
// absolute, relative and chained links, a relative path and a symlinked
// directory all conflict with the real path in both directions, and the
// lock files sit beside the real file only.
func TestLockRosterFileSharesOneLockAcrossSpellings(t *testing.T) {
	shortLockContentionWait(t)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "real.yaml")
	if err := os.WriteFile(target, []byte(lockTestRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	spellings := rosterSpellings(t, dir, target)
	for name, spelling := range spellings {
		t.Run(name, func(t *testing.T) {
			for direction, pair := range map[string][2]string{
				"held through it":  {spelling, target},
				"held on the file": {target, spelling},
			} {
				held, err := lockRosterFile(pair[0])
				if err != nil {
					t.Fatalf("%s: lock %s: %v", direction, pair[0], err)
				}
				if held.target != target {
					t.Errorf("%s: lock target = %s, want %s", direction, held.target, target)
				}
				if _, err := lockRosterFile(pair[1]); !errors.Is(err, ErrMutationLocked) {
					t.Errorf("%s: second lock on %s: error = %v, want ErrMutationLocked", direction, pair[1], err)
				}
				if err := AppendRosterUser(pair[1], "erin"); !errors.Is(err, ErrMutationLocked) {
					t.Errorf("%s: AppendRosterUser(%s) error = %v, want ErrMutationLocked", direction, pair[1], err)
				}
				if err := held.release(); err != nil {
					t.Fatal(err)
				}
			}
			again, err := lockRosterFile(spelling)
			if err != nil {
				t.Fatalf("lock after release: %v", err)
			}
			again.release() //nolint:errcheck
		})
	}
	for _, spelling := range spellings {
		if info, err := os.Lstat(spelling); err != nil || info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		for _, suffix := range rosterLockSuffixes {
			if _, err := os.Lstat(spelling + suffix); !os.IsNotExist(err) {
				t.Errorf("lock file beside the link %s (lstat err=%v)", spelling, err)
			}
		}
	}
	for _, suffix := range rosterLockSuffixes {
		if _, err := os.Stat(target + suffix); err != nil {
			t.Errorf("no %s beside the real roster: %v", suffix, err)
		}
	}
	if bytes.Contains(mustRead(t, target), []byte("erin")) {
		t.Fatal("a writer changed the roster while it was locked")
	}
}

// A link that moves between resolving the roster and holding its lock is
// refused: the lock is on the old file, which the caller no longer names.
// Neither file changes.
func TestLockRosterFileRefusesALinkRetargetedWhileLocking(t *testing.T) {
	dir := t.TempDir()
	first, second := filepath.Join(dir, "first.yaml"), filepath.Join(dir, "second.yaml")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte(lockTestRoster), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(dir, "roster.yaml")
	if err := os.Symlink(first, link); err != nil {
		t.Fatal(err)
	}
	afterRosterLockHook = func() {
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(second, link); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { afterRosterLockHook = nil })

	err := AppendRosterUser(link, "erin")
	if !errors.Is(err, ErrMutationLocked) || !strings.Contains(err.Error(), "retry") {
		t.Fatalf("error = %v, want ErrMutationLocked asking for a retry", err)
	}
	for _, path := range []string{first, second} {
		if !bytes.Equal(mustRead(t, path), []byte(lockTestRoster)) {
			t.Errorf("%s changed", path)
		}
	}
}

// A dangling link is not a new roster: creating through it fails closed
// instead of creating the file it points at, and so does every other
// writer.
func TestRosterWritersFailClosedOnADanglingLink(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.yaml")
	link := filepath.Join(dir, "roster.yaml")
	if err := os.Symlink(missing, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteMinimalRosterSkeleton(link, "admin", "Admin-pass_1"); err == nil {
		t.Fatal("WriteMinimalRosterSkeleton through a dangling link succeeded")
	}
	if err := AppendRosterUser(link, "erin"); err == nil {
		t.Fatal("AppendRosterUser through a dangling link succeeded")
	}
	if _, err := lockRosterFile(link); err == nil || errors.Is(err, ErrMutationLocked) {
		t.Fatalf("lockRosterFile(dangling link) error = %v, want a resolve error", err)
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("the dangling link's destination was created (lstat err=%v)", err)
	}
}

// A new roster under a symlinked directory is created, and locked, in the
// real directory: a lock held through the real path refuses it.
func TestNewRosterUnderALinkedDirectoryLocksTheRealPath(t *testing.T) {
	realDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(t.TempDir(), "vault")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	spelled := filepath.Join(linkDir, "new.yaml")
	lk, err := lockRosterFile(spelled)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(realDir, "new.yaml"); lk.target != want {
		t.Errorf("lock target = %s, want %s", lk.target, want)
	}
	lk.release() //nolint:errcheck

	holdRawLocks(t, filepath.Join(realDir, "new.yaml"), ".pilot-remove.lock")
	if err := WriteMinimalRosterSkeleton(spelled, "admin", "Admin-pass_1"); !errors.Is(err, ErrMutationLocked) {
		t.Fatalf("error = %v, want ErrMutationLocked", err)
	}
	if _, err := os.Stat(filepath.Join(realDir, "new.yaml")); !os.IsNotExist(err) {
		t.Fatalf("roster created under the lock (stat err=%v)", err)
	}
}

// Migrating a roster through its link migrates the real file: the link
// stays a link and the backup sits beside the real file.
func TestMigrateRosterFileThroughALinkKeepsTheLink(t *testing.T) {
	l := newLockTestLayout(t, rosterWriterCase{body: minimalValidRoster})
	result, err := MigrateRosterFile(l.link, RosterMigrationOptions{})
	if err != nil || !result.Changed {
		t.Fatalf("MigrateRosterFile() = %+v, %v", result, err)
	}
	l.assertStillALink(t)
	if filepath.Dir(result.BackupPath) != filepath.Dir(l.target) {
		t.Errorf("backup %s is not beside the real roster %s", result.BackupPath, l.target)
	}
	if !bytes.Equal(mustRead(t, result.BackupPath), l.before) {
		t.Error("backup does not hold the original bytes")
	}
	if version, err := DetectRosterSchemaVersion(mustRead(t, l.target)); err != nil || version != CurrentRosterSchemaVersion {
		t.Errorf("real roster is at schema %v (%v), want %v", version, err, CurrentRosterSchemaVersion)
	}
	if entries, _ := os.ReadDir(filepath.Dir(l.link)); len(entries) != 1 {
		t.Errorf("files beside the link: %v, want only the link", entries)
	}
}

// The plaintext an encrypted-roster mutation works on is removed with its
// lock files.
func TestDecryptRosterToTempFileCleanupRemovesLockFiles(t *testing.T) {
	requireAnsibleVault(t)
	l := newLockTestLayout(t, rosterWriterCase{body: removeFixture, encrypt: true})
	var plaintext string
	err := MutateEncryptedRosterFile(l.link, lockTestVaultPasswordFile(t), func(plaintextPath string) error {
		plaintext = plaintextPath
		return RemoveRosterUser(plaintextPath, "dave", RemoveRosterUserOptions{})
	})
	if err != nil {
		t.Fatal(err)
	}
	l.assertStillALink(t)
	for _, path := range []string{plaintext, plaintext + ".pilot-migrate.lock", plaintext + ".pilot-remove.lock"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("%s left behind (lstat err=%v)", path, err)
		}
	}
}

// Run as root (pilot-cli under `docker run`), the lock files belong to the
// roster's owner — its directory's owner for a roster about to be created
// — so the owner can still work on it without root.
func TestLockRosterFileKeepsTheOwner(t *testing.T) {
	requireRoot(t)
	const uid, gid = 12345, 12346
	dir := t.TempDir()
	if err := os.Chown(dir, uid, gid); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(existing, []byte(lockTestRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(existing, uid, gid); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{existing, filepath.Join(dir, "new.yaml")} {
		lk, err := lockRosterFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, suffix := range rosterLockSuffixes {
			info, err := os.Stat(path + suffix)
			if err != nil {
				t.Fatal(err)
			}
			if st := info.Sys().(*syscall.Stat_t); st.Uid != uid || st.Gid != gid {
				t.Errorf("%s owned by %d:%d, want %d:%d", path+suffix, st.Uid, st.Gid, uid, gid)
			}
		}
		lk.release() //nolint:errcheck
	}
}

// A roster whose directory pilot cannot write fails with a message that
// says so, before anything is read or written.
func TestLockRosterFileNeedsAWritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes any directory")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(lockTestRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) }) //nolint:errcheck
	err := AppendRosterUser(path, "erin")
	if err == nil || !strings.Contains(err.Error(), "directory must be writable") {
		t.Fatalf("error = %v, want the writable-directory message", err)
	}
	if !bytes.Equal(mustRead(t, path), []byte(lockTestRoster)) {
		t.Fatal("roster changed")
	}
}

// Only a permission error creating the temp file makes the write go in
// place; a full disk, a quota or no file descriptors fails the write and
// leaves the roster as it was, since an in-place write could stop half-way
// for the same reason (PR #148 round 5, P3-d).
func TestWriteLockedRosterFallsBackInPlaceOnlyOnPermission(t *testing.T) {
	for name, tc := range map[string]struct {
		err     error
		inPlace bool
	}{
		"EACCES": {syscall.EACCES, true},
		"EPERM":  {syscall.EPERM, true},
		"ENOSPC": {syscall.ENOSPC, false},
		"EDQUOT": {syscall.EDQUOT, false},
		"EMFILE": {syscall.EMFILE, false},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeLockTestRoster(t)
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			createRosterTemp = func(dir, pattern string) (*os.File, error) {
				return nil, &os.PathError{Op: "open", Path: filepath.Join(dir, pattern), Err: tc.err}
			}
			t.Cleanup(func() { createRosterTemp = os.CreateTemp })
			err = AppendRosterUser(path, "erin")
			if tc.inPlace {
				if err != nil {
					t.Fatalf("AppendRosterUser() = %v, want an in-place write", err)
				}
				after, _ := os.Stat(path)
				if !os.SameFile(before, after) || !bytes.Contains(mustRead(t, path), []byte("erin")) {
					t.Fatal("not written in place")
				}
				return
			}
			if err == nil || !errors.Is(err, tc.err) || !strings.Contains(err.Error(), "left unchanged") {
				t.Fatalf("AppendRosterUser() = %v, want the %v failure with the roster unchanged", err, tc.err)
			}
			if !bytes.Equal(mustRead(t, path), []byte(lockTestRoster)) {
				t.Fatal("roster changed")
			}
		})
	}
}
