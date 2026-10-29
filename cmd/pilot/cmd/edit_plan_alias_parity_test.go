package cmd

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// aliasWorkspace is a workspace whose .vault/ names reach the same roster
// more than one way — the aliasing structure a plan's scratch copy must keep
// or its AffectedFiles, Diff and warnings differ from what the apply
// reports (PR #148 review of 3a4d4a3, P2: with .vault/ipa-identity.yaml and
// .vault/group-roster.yaml both links to .vault/actual.yaml, a plan said
// [ipa-identity, main] where the apply wrote [actual, group-roster,
// ipa-identity, main]).
type aliasWorkspace struct {
	name  string
	build func(t *testing.T, dir string)
}

// aliasHosts references the roster through its default name and an alias
// only group_vars spells, the way scopeWorkspace does.
func aliasHosts(t *testing.T, dir string) {
	t.Helper()
	writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: \"Old\\\"pass#1\"\n")
	writeSyncFile(t, filepath.Join(dir, "group_vars", "freeipa-client.yml"), "freeipa_roster_file: .vault/group-roster.yaml\n")
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts:\n  h1:\n    ansible_host: 10.0.0.1\n    roles: [freeipa-client]\n    freeipa_roster_file: "+filepath.Join(dir, ".vault", "ipa-identity.yaml")+"\n")
}

func aliasWorkspaces() []aliasWorkspace {
	quotedOld := `"Old\"pass#1"`
	return []aliasWorkspace{
		{"links to one file in .vault", func(t *testing.T, dir string) {
			writeSyncFile(t, filepath.Join(dir, ".vault", "actual.yaml"), syncTestRoster(quotedOld))
			for _, name := range []string{"ipa-identity.yaml", "group-roster.yaml"} {
				if err := os.Symlink("actual.yaml", filepath.Join(dir, ".vault", name)); err != nil {
					t.Fatal(err)
				}
			}
			aliasHosts(t, dir)
		}},
		{"links to one file outside the workspace", func(t *testing.T, dir string) {
			outside := filepath.Join(t.TempDir(), "shared-roster.yaml")
			writeSyncFile(t, outside, syncTestRoster(quotedOld))
			if err := os.MkdirAll(filepath.Join(dir, ".vault"), 0o700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"ipa-identity.yaml", "group-roster.yaml"} {
				if err := os.Symlink(outside, filepath.Join(dir, ".vault", name)); err != nil {
					t.Fatal(err)
				}
			}
			aliasHosts(t, dir)
		}},
		{"a hard-linked pair", func(t *testing.T, dir string) {
			writeSyncFile(t, filepath.Join(dir, ".vault", "ipa-identity.yaml"), syncTestRoster(quotedOld))
			if err := os.Link(filepath.Join(dir, ".vault", "ipa-identity.yaml"), filepath.Join(dir, ".vault", "group-roster.yaml")); err != nil {
				t.Fatal(err)
			}
			aliasHosts(t, dir)
		}},
		{"a link chain", func(t *testing.T, dir string) {
			writeSyncFile(t, filepath.Join(dir, ".vault", "actual.yaml"), syncTestRoster(quotedOld))
			for name, target := range map[string]string{"ipa-identity.yaml": "hop.yaml", "hop.yaml": "actual.yaml", "group-roster.yaml": "actual.yaml"} {
				if err := os.Symlink(target, filepath.Join(dir, ".vault", name)); err != nil {
					t.Fatal(err)
				}
			}
			aliasHosts(t, dir)
		}},
	}
}

// normalizeReport makes the workspace's own directory nameless, so reports of
// a plan and an apply on one workspace compare equal.
func normalizeReport(dir, s string) string { return strings.ReplaceAll(s, dir, "<ws>") }

// A plan reports exactly what the apply that follows it reports — affected
// files, diff and warnings — however a workspace's .vault/ names reach its
// rosters, for a vault rotation (the sync) and for a roster step.
func TestEditPlanMatchesApplyForAliasedVaultFiles(t *testing.T) {
	t.Setenv("PILOT_TEST_NEW_ADMIN_PASSWORD", syncNewPassword)
	scenarios := map[string]editScenario{
		"vault rotation": rotationScenario(),
		"roster step":    {Version: 1, Steps: []editAction{{Action: "create_user", User: "alice"}}},
	}
	for _, ws := range aliasWorkspaces() {
		for name, scenario := range scenarios {
			t.Run(ws.name+"/"+name, func(t *testing.T) {
				dir := t.TempDir()
				ws.build(t, dir)
				plan, err := planEditScenario(dir, scenario, editAgentSessionOptions{})
				if err != nil {
					t.Fatalf("planEditScenario() error = %v", err)
				}
				apply, err := applyEditScenario(dir, "alias-parity", scenario, editAgentSessionOptions{})
				if err != nil || apply.RolledBack {
					t.Fatalf("applyEditScenario() = %+v, %v", apply, err)
				}
				if !slices.Equal(plan.AffectedFiles, apply.AffectedFiles) {
					t.Errorf("plan AffectedFiles %v, apply %v", plan.AffectedFiles, apply.AffectedFiles)
				}
				if got, want := normalizeReport(dir, plan.Diff), normalizeReport(dir, apply.Diff); got != want {
					t.Errorf("plan diff differs from apply diff:\nplan:\n%s\napply:\n%s", got, want)
				}
				if got, want := normalizeReport(dir, strings.Join(plan.Warnings, "\n")), normalizeReport(dir, strings.Join(apply.Warnings, "\n")); got != want {
					t.Errorf("plan warnings differ from apply warnings:\nplan:\n%s\napply:\n%s", got, want)
				}
			})
		}
	}
}

// A plan's scratch copy keeps which .vault/ names are one file as a relative
// symlink to one regular file among them, never a link outside the scratch:
// it is a disposable copy, and a link out would let a plan write a real
// file. Names of anything else, and a name that is the only one for its
// file, stay plain files.
func TestCopyManagedFilesToTemp_KeepsAliasingBetweenVaultNames(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "shared.yaml")
	writeSyncFile(t, outside, "shared: true\n")
	solo := filepath.Join(t.TempDir(), "solo.yaml")
	writeSyncFile(t, solo, "solo: true\n")
	writeSyncFile(t, filepath.Join(dir, ".vault", "real.yaml"), "real: true\n")
	for name, target := range map[string]string{"a.yaml": outside, "b.yaml": outside, "link-to-real.yaml": "real.yaml", "solo.yaml": solo} {
		if err := os.Symlink(target, filepath.Join(dir, ".vault", name)); err != nil {
			t.Fatal(err)
		}
	}
	writeSyncFile(t, filepath.Join(dir, ".vault", "hard-1.yaml"), "hard: true\n")
	if err := os.Link(filepath.Join(dir, ".vault", "hard-1.yaml"), filepath.Join(dir, ".vault", "hard-2.yaml")); err != nil {
		t.Fatal(err)
	}
	writeSyncFile(t, filepath.Join(dir, "group_vars", "g.yml"), "g: 1\n")
	if err := os.Symlink(filepath.Join(dir, "group_vars", "g.yml"), filepath.Join(dir, "group_vars", "g-alias.yml")); err != nil {
		t.Fatal(err)
	}

	tempDir, cleanup, err := copyManagedFilesToTemp(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	wantLinks := map[string]string{".vault/b.yaml": "a.yaml", ".vault/link-to-real.yaml": "real.yaml", ".vault/hard-2.yaml": "hard-1.yaml"}
	err = filepath.WalkDir(tempDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(tempDir, path)
		rel = filepath.ToSlash(rel)
		target, linkErr := os.Readlink(path)
		isLink := linkErr == nil
		want, shouldLink := wantLinks[rel]
		switch {
		case isLink != shouldLink:
			t.Errorf("%s: symlink = %v, want %v", rel, isLink, shouldLink)
		case isLink && target != want:
			t.Errorf("%s -> %q, want the relative link %q", rel, target, want)
		}
		if isLink {
			if resolved, err := filepath.EvalSymlinks(path); err != nil || !strings.HasPrefix(resolved, resolveSymlinks(t, tempDir)+string(filepath.Separator)) {
				t.Errorf("%s resolves to %q (%v), outside the scratch", rel, resolved, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]string{".vault/a.yaml": "shared: true\n", ".vault/b.yaml": "shared: true\n", ".vault/solo.yaml": "solo: true\n", ".vault/hard-2.yaml": "hard: true\n", "group_vars/g-alias.yml": "g: 1\n"} {
		if got, _ := os.ReadFile(filepath.Join(tempDir, filepath.FromSlash(rel))); string(got) != want {
			t.Errorf("%s = %q, want %q", rel, got, want)
		}
	}
	// Writing through an alias in the scratch changes its file and no real one.
	if err := os.WriteFile(filepath.Join(tempDir, ".vault", "b.yaml"), []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(tempDir, ".vault", "a.yaml")); string(got) != "changed\n" {
		t.Errorf("a.yaml = %q; writing b.yaml did not reach the file they share", got)
	}
	if got, _ := os.ReadFile(outside); string(got) != "shared: true\n" {
		t.Errorf("the real file behind the links was written: %q", got)
	}
}

func resolveSymlinks(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}
