package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveTargetsPositional(t *testing.T) {
	// Save and restore globals
	runInventory, runLimit, runFromStdin, runDiscover = "", "", false, ""
	defer func() {
		runInventory, runLimit, runFromStdin = "", "", false
		runDiscover = ""
	}()

	tgts, err := resolveTargets([]string{"playbook.yml"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tgts) != 1 || tgts[0].Playbook != "playbook.yml" {
		t.Errorf("unexpected: %+v", tgts)
	}
}

func TestResolveTargetsMutualExclusionPositionalAndFromStdin(t *testing.T) {
	oldFs := runFromStdin
	oldInv := runInventory
	defer func() { runFromStdin = oldFs; runInventory = oldInv }()
	runFromStdin = true
	runInventory = ""
	_, err := resolveTargets([]string{"foo.yml"})
	if err == nil {
		t.Fatal("expected error for positional + --from-stdin")
	}
	if !strings.Contains(err.Error(), "cannot be combined") {
		t.Errorf("expected 'cannot be combined' in error, got: %v", err)
	}
}

func TestResolveTargetsMutualExclusionFromStdinAndDiscover(t *testing.T) {
	oldFs := runFromStdin
	oldD := runDiscover
	oldInv := runInventory
	defer func() { runFromStdin = oldFs; runDiscover = oldD; runInventory = oldInv }()
	runFromStdin = true
	runDiscover = "playbooks/"
	runInventory = ""
	_, err := resolveTargets(nil)
	if err == nil {
		t.Fatal("expected error for --from-stdin + --discover")
	}
}

func TestParsePlainLines(t *testing.T) {
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "a.yml"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(tmp, "b.yml"), []byte("x"), 0o644)

	// parsePlainLines is the inner helper that does NOT filter comments;
	// comment filtering is done by the caller. Test the raw behavior.
	lines := []string{
		filepath.Join(tmp, "a.yml"),
		filepath.Join(tmp, "b.yml"),
	}
	got, err := parsePlainLines(lines, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 targets, got %d: %+v", len(got), got)
	}
}

func TestReadTargetsFromStdinSkipsComments(t *testing.T) {
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "a.yml"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(tmp, "b.yml"), []byte("x"), 0o644)
	lines := []string{
		"# leading comment",
		"",
		filepath.Join(tmp, "a.yml"),
		"   ",
		filepath.Join(tmp, "b.yml"),
	}
	got, err := readTargetsFromStdinLines(lines, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 (comments skipped), got %d: %+v", len(got), got)
	}
}

func TestParsePlainLinesGlob(t *testing.T) {
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "a.yml"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(tmp, "b.yml"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(tmp, "c.txt"), []byte("x"), 0o644)

	lines := []string{filepath.Join(tmp, "*.yml")}
	got, err := parsePlainLines(lines, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 matches for *.yml, got %d: %+v", len(got), got)
	}
}

func TestParseJSONLinesAutoDetect(t *testing.T) {
	// First non-empty line starts with '{' → JSON mode for the whole batch.
	lines := []string{
		`{"playbook":"/p1.yml","inventory":"/inv","limit":"web01"}`,
		`{"playbook":"/p2.yml","limit":"db"}`,
	}
	got, err := readTargetsFromStdinLines(lines, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
	if got[0].Inventory != "/inv" {
		t.Errorf("first inventory: %q", got[0].Inventory)
	}
	if got[0].Limit != "web01" {
		t.Errorf("first limit: %q", got[0].Limit)
	}
	if got[1].Limit != "db" {
		t.Errorf("second limit: %q", got[1].Limit)
	}
}

func TestParseJSONLines(t *testing.T) {
	lines := []string{
		`{"playbook":"/p1.yml","inventory":"/inv"}`,
		`{"playbook":"/p2.yml","limit":"db"}`,
	}
	got, err := parseJSONLines(lines, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
	if got[0].Playbook != "/p1.yml" || got[0].Inventory != "/inv" {
		t.Errorf("first target wrong: %+v", got[0])
	}
	if got[1].Playbook != "/p2.yml" || got[1].Limit != "db" {
		t.Errorf("second target wrong: %+v", got[1])
	}
}

func TestParseJSONLinesInvalid(t *testing.T) {
	_, err := parseJSONLines([]string{`{not valid json`}, "", "")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseJSONLinesMissingPlaybook(t *testing.T) {
	_, err := parseJSONLines([]string{`{"inventory":"/inv"}`}, "", "")
	if err == nil {
		t.Fatal("expected error for missing playbook")
	}
	if !strings.Contains(err.Error(), "playbook") {
		t.Errorf("error should mention 'playbook': %v", err)
	}
}

func TestDiscoverTargetsGlob(t *testing.T) {
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "a.yml"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(tmp, "b.yml"), []byte("x"), 0o644)
	pattern := filepath.Join(tmp, "*.yml")
	got, err := discoverTargets(pattern, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2, got %d", len(got))
	}
}

func TestDiscoverTargetsDirectory(t *testing.T) {
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "a.yml"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(tmp, "b.yaml"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(tmp, "c.txt"), []byte("x"), 0o644)
	got, err := discoverTargets(tmp, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 yml/yaml files, got %d: %+v", len(got), got)
	}
}

func TestDiscoverTargetsSingleFile(t *testing.T) {
	tmp := t.TempDir()
	pb := filepath.Join(tmp, "single.yml")
	_ = os.WriteFile(pb, []byte("x"), 0o644)
	got, err := discoverTargets(pb, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Playbook != pb {
		t.Errorf("expected 1 target %q, got %+v", pb, got)
	}
}

func TestDiscoverTargetsNoMatch(t *testing.T) {
	_, err := discoverTargets("/nonexistent/path/*.yml", "", "")
	if err == nil {
		t.Fatal("expected error for no matches")
	}
}

func TestDiscoverTargetsEmptyDir(t *testing.T) {
	tmp := t.TempDir()
	_, err := discoverTargets(tmp, "", "")
	if err == nil {
		t.Fatal("expected error for empty directory")
	}
}

func TestHasGlobMeta(t *testing.T) {
	for _, s := range []string{"a", "/x/y.yml", "no-glob-here"} {
		if hasGlobMeta(s) {
			t.Errorf("expected no glob meta in %q", s)
		}
	}
	for _, s := range []string{"*.yml", "a?b", "[abc]"} {
		if !hasGlobMeta(s) {
			t.Errorf("expected glob meta in %q", s)
		}
	}
}

func TestShortIDOf(t *testing.T) {
	if got := shortIDOf("12345678abcdef"); got != "12345678" {
		t.Errorf("shortIDOf: %q", got)
	}
	if got := shortIDOf("abc"); got != "abc" {
		t.Errorf("shortIDOf short: %q", got)
	}
}

func TestTruncForSummary(t *testing.T) {
	if got := truncForSummary("a\nb", 10); got != "a b" {
		t.Errorf("newlines: %q", got)
	}
	if got := truncForSummary("hello world this is a long line", 10); got != "hello worl…" {
		t.Errorf("truncate: %q", got)
	}
}

func TestReadTargetsFromStdinEmpty(t *testing.T) {
	_, err := readTargetsFromStdinLines([]string{"", "  ", "# comment"}, "", "")
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestBatchResultCounting(t *testing.T) {
	rs := []batchResult{
		{OK: true}, {OK: true}, {OK: false},
	}
	s, f := countByOK(rs)
	if s != 2 || f != 1 {
		t.Errorf("countByOK: got %d/%d, want 2/1", s, f)
	}
	if countFailures(rs) != 1 {
		t.Errorf("countFailures: %d", countFailures(rs))
	}
}

// ----- ANSIBLE_INVENTORY env var fallback (Item 1) -----

func TestResolveTargets_AnsibleInventoryEnvFallback_Positional(t *testing.T) {
	// Clear CLI flag, set env var; expect env to be applied to the
	// resolved target.
	oldInv := runInventory
	oldFs := runFromStdin
	oldD := runDiscover
	t.Setenv("ANSIBLE_INVENTORY", "/etc/ansible/from-env.ini")
	runInventory = ""
	runFromStdin = false
	runDiscover = ""
	defer func() {
		runInventory = oldInv
		runFromStdin = oldFs
		runDiscover = oldD
	}()

	tgts, err := resolveTargets([]string{"site.yml"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tgts) != 1 {
		t.Fatalf("expected 1 target, got %d", len(tgts))
	}
	if tgts[0].Inventory != "/etc/ansible/from-env.ini" {
		t.Errorf("expected inventory from env, got %q", tgts[0].Inventory)
	}
}

func TestResolveTargets_InventoryFlagBeatsEnv(t *testing.T) {
	// Explicit -i flag must win over ANSIBLE_INVENTORY env var.
	oldInv := runInventory
	oldFs := runFromStdin
	oldD := runDiscover
	t.Setenv("ANSIBLE_INVENTORY", "/etc/ansible/from-env.ini")
	runInventory = "/etc/ansible/from-flag.ini"
	runFromStdin = false
	runDiscover = ""
	defer func() {
		runInventory = oldInv
		runFromStdin = oldFs
		runDiscover = oldD
	}()

	tgts, err := resolveTargets([]string{"site.yml"})
	if err != nil {
		t.Fatal(err)
	}
	if tgts[0].Inventory != "/etc/ansible/from-flag.ini" {
		t.Errorf("flag should beat env, got %q", tgts[0].Inventory)
	}
}

func TestResolveTargets_NoEnvNoFlag(t *testing.T) {
	// Neither -i nor ANSIBLE_INVENTORY → inventory stays empty
	// (playbook's own hosts: clause will be used at ansible-run time).
	oldInv := runInventory
	oldFs := runFromStdin
	oldD := runDiscover
	t.Setenv("ANSIBLE_INVENTORY", "")
	runInventory = ""
	runFromStdin = false
	runDiscover = ""
	defer func() {
		runInventory = oldInv
		runFromStdin = oldFs
		runDiscover = oldD
	}()

	tgts, err := resolveTargets([]string{"site.yml"})
	if err != nil {
		t.Fatal(err)
	}
	if tgts[0].Inventory != "" {
		t.Errorf("expected empty inventory, got %q", tgts[0].Inventory)
	}
}

func TestParseJSONLines_InventoryBeatsEnv(t *testing.T) {
	// Per-line inventory in JSONL must beat env fallback.
	lines := []string{
		`{"playbook":"/p1.yml","inventory":"/from-line.ini"}`,
	}
	got, err := parseJSONLines(lines, "/from-env.ini", "")
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Inventory != "/from-line.ini" {
		t.Errorf("per-line inventory should beat env, got %q", got[0].Inventory)
	}
}

func TestParseJSONLines_EmptyInheritsEnv(t *testing.T) {
	// Per-line inventory empty → env fallback fills in.
	lines := []string{
		`{"playbook":"/p1.yml"}`,
	}
	got, err := parseJSONLines(lines, "/from-env.ini", "webservers")
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Inventory != "/from-env.ini" {
		t.Errorf("empty inventory should inherit env, got %q", got[0].Inventory)
	}
	if got[0].Limit != "webservers" {
		t.Errorf("empty limit should inherit default, got %q", got[0].Limit)
	}
}

func TestDiscoverTargets_PicksUpEnv(t *testing.T) {
	// --discover with env set should propagate env inventory to each
	// discovered target.
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "a.yml"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(tmp, "b.yml"), []byte("x"), 0o644)

	got, err := discoverTargets(tmp, "/from-env.ini", "web*")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
	for _, g := range got {
		if g.Inventory != "/from-env.ini" {
			t.Errorf("target %q missing env inventory: %q", g.Playbook, g.Inventory)
		}
		if g.Limit != "web*" {
			t.Errorf("target %q missing default limit: %q", g.Playbook, g.Limit)
		}
	}
}

// ----- Item 3: JSONL parsing of all 11 new ansible-playbook flags -----

func TestParseJSONLines_AllNewFields(t *testing.T) {
	// One JSONL line that exercises every new field. Verifies that
	// unmarshal accepts them and that pointer fields preserve
	// "true"/"false" distinction (not collapsed to zero value).
	yes := true
	no := false
	line := `{"playbook":"/p1.yml","inventory":"/inv","limit":"web01",` +
		`"tags":["a","b"],"skip_tags":["x"],` +
		`"extra_vars":{"env":"prod","version":1.2},` +
		`"become":true,"forks":5,"user":"deploy","connection":"local",` +
		`"vault_password_file":"/tmp/.vp","diff":true,"timeout":60,"flush_cache":false}`
	got, err := parseJSONLines([]string{line}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 target, got %d", len(got))
	}
	tgt := got[0]
	if tgt.Inventory != "/inv" {
		t.Errorf("inventory: %q", tgt.Inventory)
	}
	if tgt.Limit != "web01" {
		t.Errorf("limit: %q", tgt.Limit)
	}
	if len(tgt.Tags) != 2 || tgt.Tags[0] != "a" || tgt.Tags[1] != "b" {
		t.Errorf("tags: %v", tgt.Tags)
	}
	if len(tgt.SkipTags) != 1 || tgt.SkipTags[0] != "x" {
		t.Errorf("skip_tags: %v", tgt.SkipTags)
	}
	if tgt.ExtraVars["env"] != "prod" {
		t.Errorf("extra_vars[env]: %v", tgt.ExtraVars["env"])
	}
	if tgt.Become == nil || *tgt.Become != true {
		t.Errorf("become should be &true, got %v", tgt.Become)
	}
	if tgt.Forks == nil || *tgt.Forks != 5 {
		t.Errorf("forks should be &5, got %v", tgt.Forks)
	}
	if tgt.User != "deploy" {
		t.Errorf("user: %q", tgt.User)
	}
	if tgt.Connection != "local" {
		t.Errorf("connection: %q", tgt.Connection)
	}
	if tgt.VaultPasswordFile != "/tmp/.vp" {
		t.Errorf("vault_password_file: %q", tgt.VaultPasswordFile)
	}
	if tgt.Diff == nil || *tgt.Diff != true {
		t.Errorf("diff should be &true, got %v", tgt.Diff)
	}
	if tgt.Timeout == nil || *tgt.Timeout != 60 {
		t.Errorf("timeout should be &60, got %v", tgt.Timeout)
	}
	if tgt.FlushCache == nil || *tgt.FlushCache != false {
		t.Errorf("flush_cache should be &false (preserved!), got %v", tgt.FlushCache)
	}
	// Reference the yes/no locals so the compiler doesn't complain.
	_ = yes
	_ = no
}

func TestParseJSONLines_OptionalFieldsOmitted(t *testing.T) {
	// A minimal JSONL line — no new fields. Backward-compat check.
	line := `{"playbook":"/p.yml"}`
	got, err := parseJSONLines([]string{line}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	tgt := got[0]
	if tgt.Tags != nil {
		t.Errorf("tags should be nil, got %v", tgt.Tags)
	}
	if tgt.Become != nil {
		t.Errorf("become should be nil (not set), got %v", tgt.Become)
	}
	if tgt.Forks != nil {
		t.Errorf("forks should be nil, got %v", tgt.Forks)
	}
	if tgt.Diff != nil {
		t.Errorf("diff should be nil, got %v", tgt.Diff)
	}
	if tgt.Timeout != nil {
		t.Errorf("timeout should be nil, got %v", tgt.Timeout)
	}
	if tgt.FlushCache != nil {
		t.Errorf("flush_cache should be nil, got %v", tgt.FlushCache)
	}
}

func TestParseJSONLines_ExtraVarsNested(t *testing.T) {
	// extra_vars can be a nested object — must round-trip via JSON.
	line := `{"playbook":"/p.yml","extra_vars":{"a":{"b":{"c":1}}}}`
	got, err := parseJSONLines([]string{line}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	a, ok := got[0].ExtraVars["a"].(map[string]any)
	if !ok {
		t.Fatalf("extra_vars.a not a nested object: %T", got[0].ExtraVars["a"])
	}
	b, ok := a["b"].(map[string]any)
	if !ok {
		t.Fatalf("extra_vars.a.b not a nested object: %T", a["b"])
	}
	if c, ok := b["c"].(float64); !ok || c != 1 {
		t.Errorf("extra_vars.a.b.c = %v", b["c"])
	}
}

// readTargetsFromStdinLines is a testable wrapper that uses an
// in-memory line list instead of os.Stdin. We redefine the entry point
// here for tests.
func readTargetsFromStdinLines(lines []string, defaultInventory, defaultLimit string) ([]playbookTarget, error) {
	nonEmpty := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		nonEmpty = append(nonEmpty, l)
	}
	if len(nonEmpty) == 0 {
		return nil, fmtErr("no input on stdin")
	}
	if strings.HasPrefix(nonEmpty[0], "{") {
		return parseJSONLines(nonEmpty, defaultInventory, defaultLimit)
	}
	return parsePlainLines(nonEmpty, defaultInventory, defaultLimit)
}

func fmtErr(s string) error { return &strErr{s} }

type strErr struct{ s string }

func (e *strErr) Error() string { return e.s }

// Avoid unused import linting in this file when JSON might not be used
var _ = json.Marshal
