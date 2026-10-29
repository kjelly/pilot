package cmd

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// vaultValueKinds are the forms an ipa_admin_password can take in
// .vault/main.yaml, as written before (old) and after (new) a save.
var vaultValueKinds = map[string][2]string{
	"literal":    {`"Lit-pass_1"`, `"Lit-pass_2"`},
	"!unsafe":    {`!unsafe "Uns{{pass_1"`, `!unsafe "Uns{{pass_2"`},
	"template":   {`"{{ lookup('env', 'OLD') }}"`, `"{{ lookup('env', 'NEW') }}"`},
	"unquoted":   {`12345678`, `87654321`},
	"!vault":     {"!vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6162", "!vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6364"},
	"absent":     {"", ""},
	"non-scalar": {"[a, b]", "[c, d]"},
}

// wantVaultSaveLine is the line a save from old to new kind reports
// before any roster is looked at ("" for none: a sync, or no rotation).
// Each line is judged on the value it is about (PR #148 round 5 P3-c,
// round 6 P3-6): what to do with the new value on the new value, what
// pilot cannot know about the old one on the old one.
func wantVaultSaveLine(old, new string) string {
	replaced := old != "absent" && new != "absent"
	switch {
	case new == "template":
		return "未同步名冊：新的 ipa_admin_password 含 {{"
	case new == "unquoted", new == "non-scalar":
		return "未同步名冊：ipa_admin_password 沒加引號"
	case replaced && (old == "!vault" || new == "!vault"):
		return "未同步名冊：ipa_admin_password 原本或現在是 !vault 加密值"
	case replaced && old == "template":
		return "未同步名冊：原本的 ipa_admin_password 含 {{"
	case replaced && (old == "unquoted" || old == "non-scalar"):
		return "未同步名冊：原本的 ipa_admin_password 沒加引號"
	}
	return ""
}

// Every old x new value kind gets the line wantVaultSaveLine names, and
// only that one; no line ever shows the value.
func TestVaultSaveLineForEveryValueKindPair(t *testing.T) {
	for oldKind, oldValues := range vaultValueKinds {
		for newKind, newValues := range vaultValueKinds {
			t.Run(oldKind+" -> "+newKind, func(t *testing.T) {
				doc := func(value string) []byte {
					if value == "" {
						return []byte("other: x\n")
					}
					return []byte("other: x\nipa_admin_password: " + value + "\n")
				}
				previous, saved := doc(oldValues[0]), doc(newValues[1])
				dir := t.TempDir()
				vault := filepath.Join(dir, ".vault", "main.yaml")
				writeSyncFile(t, vault, string(previous))
				r := newEditRouterModel(dir)
				sync, refused := prepareVaultRosterSync(&r, dir, vault, previous, saved)
				if refused != "" {
					t.Fatalf("refused: %s", refused)
				}
				lines := sync.commit()
				want := wantVaultSaveLine(oldKind, newKind)
				var got []string
				for _, l := range lines {
					got = append(got, l.text)
				}
				switch {
				case want == "" && len(got) != 0:
					t.Fatalf("lines = %q, want none", got)
				case want != "" && (len(got) != 1 || !strings.HasPrefix(got[0], want)):
					t.Fatalf("lines = %q, want one starting %q", got, want)
				}
				for _, l := range got {
					for _, v := range append(oldValues[:], newValues[:]...) {
						if v != "" && strings.Contains(l, strings.Trim(v, `"`)) {
							t.Fatalf("line %q shows a value", l)
						}
					}
				}
			})
		}
	}
}

// A previous vault whose YAML aliases refer to themselves reads as no
// password, so the save syncs no roster and does not crash (PR #148 round
// 11). The previous vault is read from disk, so it can differ from the
// document the editor loaded; the child process keeps a stack overflow from
// taking the package with it.
func TestPrepareVaultRosterSyncSurvivesACyclicPreviousVault(t *testing.T) {
	for name, previous := range map[string]string{
		"cyclic root":  "&r\n<<: *r\nipa_admin_password: \"Old-pass_1\"\n",
		"cyclic value": "ipa_admin_password: &p\n  <<: *p\n",
		"fan-out":      fanOutRosterLevels(40) + "<<: *a39\n",
	} {
		t.Run(name, func(t *testing.T) {
			runIsolated(t, 20*time.Second, func(t *testing.T) {
				dir := t.TempDir()
				vault := filepath.Join(dir, ".vault", "main.yaml")
				roster := filepath.Join(dir, ".vault", "ipa-identity.yaml")
				writeSyncFile(t, vault, previous)
				writeSyncFile(t, roster, syncTestRoster(`"Old-pass_1"`))
				before := snapshotFiles(t, vault, roster)
				r := newEditRouterModel(dir)
				sync, refused := prepareVaultRosterSync(&r, dir, vault, []byte(previous), []byte("ipa_admin_password: \"New-pass_2\"\n"))
				if refused != "" {
					t.Fatalf("refused: %s", refused)
				}
				if lines := sync.commit(); len(lines) != 0 {
					t.Fatalf("lines = %v, want none: nothing is known of the old password", lines)
				}
				assertUnchanged(t, before)
			})
		})
	}
}
